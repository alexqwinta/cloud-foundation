#!/usr/bin/env python3
import argparse
import json
import sys
import os

SEV = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

def check_s3(snap):
    f = []
    for b in snap.get("s3_buckets", []):
        name = b["name"]
        if not b.get("default_encryption"):
            f.append(("HIGH", "s3", name, "No default encryption. Objects stored in the clear."))
        if not b.get("block_public_access"):
            f.append(("HIGH", "s3", name, "No Block Public Access. Bucket can be exposed to the internet."))
        if not b.get("tls_only_policy"):
            f.append(("MEDIUM", "s3", name, "No TLS-only bucket policy. Plaintext requests accepted."))
        if not b.get("versioning"):
            f.append(("LOW", "s3", name, "Versioning off. No recovery from overwrite or delete."))
    return f

def check_security_groups(snap):
    f = []
    for sg in snap.get("security_groups", []):
        for rule in sg.get("ingress", []):
            if rule.get("cidr") == "0.0.0.0/0":
                f.append(("HIGH", "sg", sg["id"], f"Ingress on port {rule.get('port')} open to 0.0.0.0/0."))
    return f

def check_vpc_flow_logs(snap):
    f = []
    for v in snap.get("vpcs", []):
        if not v.get("flow_logs"):
            f.append(("MEDIUM", "vpc", v["id"], "No VPC flow logs. You cannot investigate traffic you never recorded."))
    return f

def check_iam(snap):
    f = []
    for r in snap.get("iam_roles", []):
        if r.get("has_wildcard_allow"):
            f.append(("HIGH", "iam", r["name"], "Role policy allows wildcard or service-wide actions (s3:*, kms:*)."))
        if not r.get("has_destructive_deny"):
            f.append(("MEDIUM", "iam", r["name"], "No explicit deny on destructive actions (delete bucket, stop trail, delete key)."))
    return f

def check_kms(snap):
    f = []
    for k in snap.get("kms_keys", []):
        if not k.get("rotation"):
            f.append(("MEDIUM", "kms", k["id"], "Key rotation disabled."))
    return f

def check_cloudtrail(snap):
    f = []
    trails = snap.get("cloudtrails", [])
    if not trails:
        f.append(("HIGH", "cloudtrail", "-", "No CloudTrail found. The account has no audit record."))
    for t in trails:
        name = t["name"]
        if not t.get("multi_region"):
            f.append(("MEDIUM", "cloudtrail", name, "Trail is single-region. Activity in other regions is invisible."))
        if not t.get("log_file_validation"):
            f.append(("MEDIUM", "cloudtrail", name, "Log file validation off. Log tampering is undetectable."))
        if not t.get("data_events"):
            f.append(("MEDIUM", "cloudtrail", name, "No S3 data events. Object reads and writes are not recorded."))
        if not t.get("kms_encrypted"):
            f.append(("LOW", "cloudtrail", name, "Trail logs not encrypted with a customer-managed key."))
    return f

ALL_CHECKS = [check_s3, check_security_groups, check_vpc_flow_logs, check_iam, check_kms, check_cloudtrail]

def run_checks(snap):
    findings = []
    for c in ALL_CHECKS:
        findings.extend(c(snap))
    findings.sort(key=lambda x: -SEV[x[0]])
    return findings

def collect_live(project, region):
    import boto3
    tagval = project
    snap = {"s3_buckets": [], "security_groups": [], "vpcs": [], "iam_roles": [], "kms_keys": [], "cloudtrails": []}
    
    s3 = boto3.client("s3", region_name=region)
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=name).get("TagSet", [])}
        except Exception:
            tags = {}
        if tags.get("Project") != tagval:
            continue
        enc = pab = tls = ver = False
        try:
            s3.get_bucket_encryption(Bucket=name)
            enc = True
        except Exception: pass
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            pab = all(cfg.values())
        except Exception: pass
        try:
            pol = s3.get_bucket_policy(Bucket=name)["Policy"]
            tls = "aws:SecureTransport" in pol
        except Exception: pass
        try:
            ver = s3.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
        except Exception: pass
        snap["s3_buckets"].append({"name": name, "default_encryption": enc, "block_public_access": pab, "tls_only_policy": tls, "versioning": ver})

    ec2 = boto3.client("ec2", region_name=region)
    flt = [{"Name": "tag:Project", "Values": [tagval]}]
    for sg in ec2.describe_security_groups(Filters=flt).get("SecurityGroups", []):
        ingress = []
        for p in sg.get("IpPermissions", []):
            for rng in p.get("IpRanges", []):
                ingress.append({"port": p.get("FromPort"), "cidr": rng.get("CidrIp")})
        snap["security_groups"].append({"id": sg["GroupId"], "ingress": ingress})

    for v in ec2.describe_vpcs(Filters=flt).get("Vpcs", []):
        fl = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [v["VpcId"]]}]).get("FlowLogs", [])
        snap["vpcs"].append({"id": v["VpcId"], "flow_logs": len(fl) > 0})

    iam = boto3.client("iam")
    for r in iam.list_roles().get("Roles", []):
        name = r["RoleName"]
        if not name.startswith(project):
            continue
        wild = destructive_deny = False
        for pn in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            doc = iam.get_role_policy(RoleName=name, PolicyName=pn)["PolicyDocument"]
            for st in doc.get("Statement", []):
                acts = st.get("Action", [])
                acts = [acts] if isinstance(acts, str) else acts
                if st.get("Effect") == "Allow" and any(a == "*" or a.endswith(":*") for a in acts):
                    wild = True
                if st.get("Effect") == "Deny":
                    destructive_deny = True
        snap["iam_roles"].append({"name": name, "has_wildcard_allow": wild, "has_destructive_deny": destructive_deny})

    kms = boto3.client("kms", region_name=region)
    for k in kms.list_keys().get("Keys", []):
        kid = k["KeyId"]
        try:
            meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            if meta.get("KeyState") in ("PendingDeletion", "PendingReplicaDeletion"):
                continue
            tags = {t["TagKey"]: t["TagValue"] for t in kms.list_resource_tags(KeyId=kid).get("Tags", [])}
            if tags.get("Project") != tagval:
                continue
            rot = kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled", False)
            snap["kms_keys"].append({"id": kid, "rotation": rot})
        except Exception: pass

    ct = boto3.client("cloudtrail", region_name=region)
    for t in ct.describe_trails().get("trailList", []):
        if project not in t.get("Name", ""):
            continue
        try:
            sel = ct.get_event_selectors(TrailName=t["TrailARN"]).get("EventSelectors", [])
            data_ev = any(es.get("DataResources") for es in sel)
            snap["cloudtrails"].append({
                "name": t["Name"],
                "multi_region": t.get("IsMultiRegionTrail", False),
                "log_file_validation": t.get("LogFileValidationEnabled", False),
                "data_events": data_ev,
                "kms_encrypted": t.get("KmsKeyId") is not None
            })
        except Exception: pass

    return snap

def report(findings):
    if not findings:
        print("PASS. No findings. This foundation is hardened.")
        return 0
    print(f"FAIL. {len(findings)} finding(s):\n")
    for sev, svc, res, msg in findings:
        print(f" [{sev:6}] {svc:11} {res:22} {msg}")
    highs = sum(1 for f in findings if f[0] == "HIGH")
    print(f"\n{highs} HIGH severity. Fix these first. Then re-run this scanner.")
    return 1

def main():
    ap = argparse.ArgumentParser(description="hwz-scan")
    ap.add_argument("--project", default="hwz")
    ap.add_argument("--region", default="eu-central-1")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        print("[*] Running self-test logic...")
        test_snap = {
            "s3_buckets": [
                {"name": "test-weak-bucket", "default_encryption": False, "block_public_access": False, "tls_only_policy": False, "versioning": False}
            ]
        }
        res = run_checks(test_snap)
        sys.exit(report(res))
        
    snap = collect_live(a.project, a.region)
    sys.exit(report(run_checks(snap)))

if __name__ == "__main__":
    main()
EOF


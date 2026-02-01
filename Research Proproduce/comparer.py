import json


def runAudit(truth,report):
    with open(report, 'r') as f:
        data = json.load(f)
        reported_ids = [flow['id'] for flow in data['flows']]
        print("Reported IDs:", reported_ids)

    ## Comparing Reported data with real data
    hidden_found = False
    with open(truth, 'r') as f:
        for line in f:
            if "flow_id:" in line:
                actual_id = line.split(",")[0].split(":")[1]

                if actual_id not in reported_ids:
                    print(f"Hidden Flow Detected! ID: {actual_id}")
                    print(f"Detail: {line.strip()}")
                    hidden_found = True
                else:
                    print(f"[+] Flow {actual_id} verified.")

    if not hidden_found:
        print("Audit Completed")
    else:
        print("SECURITY INCIDENT FOUND")

runAudit("network.txt","report.json")
import json
import time

def print_execution_time(start, end):
    total_time = (end - start) * 1000
    print(f"{total_time}ms")

def runAudit(truth,report):
    start_time = time.time()
    with open(report, 'r') as f:
        data = json.load(f)
        reported_ids = [flow['id'] for flow in data['flows']]
        print("Reported IDs:", reported_ids)

    ## Comparing Reported data with real data
    hidden_found = False
    with open(truth, 'r') as f:
        #file storing malicious flow rules
        with open("malicious_message_store.txt","w") as message_store:
            message_store.write("MALICIOUS FLOW RULES DETECTED:\n")

        for line in f:
            if "flow_id:" in line:
                actual_id = line.split(",")[0].split(":")[1]

                if actual_id not in reported_ids:
                    print(f"Hidden Flow Detected! ID: {actual_id}")
                    print(f"Detail: {line.strip()}")
                    hidden_found = True
                    #store flow rule
                    with open("malicious_message_store.txt", "a") as message_store:
                        message_store.write(f"{line.strip()}\n")
                else:
                    print(f"[+] Flow {actual_id} verified.")

    if not hidden_found:
        print("Audit Completed")
        with open("malicious_message_store.txt", "a") as message_store:
            message_store.write("none\n")
    else:
        print("SECURITY INCIDENT FOUND")

    end_time = time.time()
    print_execution_time(start_time,end_time)

runAudit("network.txt","report.json")
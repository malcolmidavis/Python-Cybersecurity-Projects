#Script: Password Audit and Investigation Logger
#Purpose: Audit password hashes, identify weak credentials using a rainbow table, and document investigation findings in a log.

#Import Standard Python Libraries
import itertools
import hashlib
import logging
import platform
import time
import datetime
import socket

#Import Third-Party Libraries
from prettytable import PrettyTable
import psutil

#Program Dictionaries
evidence_hashes = {
"twilson": "8a5a317fb3ceef3c50a38d23b72c0b2fac3d25b0526ff69a4c26635c275ff3dd",
"jsmith": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
"cmoore": "2b4b402b23813263e2aae15d78f914689a0b0975ea38debdf1e120bd4c6bca8d",
"hwhite": "0a21ee3e83332d31765ee19231b60c9946fcc086dc420eed65ce535ee4812ffb",
"mgarcia": "1a5751be8a96e5976c3ac5cc655d299186dd9e378431e67174ba59842bbb2ab5",
"young": "39865d544968cf18ca8b65781304e39f99fbbdb744c562ff78399c902d2ca7ff",
"jthomas": "a004441a4bba56dd35a43d0f2fd57fd476d97620523aadb73cb69b523466d590",
"alee": "ebbfb53547b778a125159d0de39c0be05b019fa447e6d358bf1aae65926aa553",
"mjackson": "af209f90d03d28bcd905dadd3d0d34b96104504dd70a512ae534dd385aede66e",
"allen": "34abb97ac66bf776d6467c7ead1ece483db87d8eb7667ad1583e661b8bb031b7",
"rjohnson": "59d937723564937cd1441370c7c7cd9f669f93253dcfab8c50affad3b18d645e",
"kbrown": "19513fdc9da4fb72a4a05eb66917548d3c90ff94d5419e1f2363eea89dfee1dd",
"khall": "cbe1b7d7f446e134f78cefe973dfbbde9969b81e541853b56eec04a77a6505c3",
"dmartinez": "c8b752313ecaec4fc1fe4942e91a299aad81ce83612b10779911fd3f662e0c80",
"rlewis": "bdfe076cf1338f4c28f05102121ea7c392d200691c8fa5655e648f1fc04c872c",
"awalker": "9053ae1e6e9e9f7812f7f6a0fd6b3728c1785ad35432de1b6c21a2cbb74b8f8f",
"jharris": "d0ef7f8fbadf7da15d33d05ed16e4f0749f118478065d7d31c7157e4d121478d",
"mrobinson": "01cb92dfff4091c2bee0f343b2af049fb39b45c08a1e5132b834e12e037d919d",
"king": "f6b39ef3ed573ac329db2ba4554f4bc9e7da3bb529c368dd2338b327b03be28f",
"dclark": "e807b101a1033737035afea7b9302182995e624190f32b0b4d53688ead8596d5"
}

rainbow_table = {}
investigation_results = {}
result_counts = {}
pw_counts = {}

#Display a welcome message that includes your name and the title of the assignment
print("=" * 70)
print("Password Audit and Investigation Logger by Malcolm Davis")
print("=" * 70)
print()

#Get information from the user
investigator_first = input("Please enter the Investigator's First Name: ")
investigator_last = input("Please enter the Investigator's Last Name: ")
organization = input("Please enter the Investigator's Organization: ")
investigation_purpose = input("Please enter the investigation purpose: ")

print()

#Store the created log file filename in log_file
timestamp = int(time.time())

log_file = (
    f"{investigator_first.title()}"
    f"{investigator_last.title()}"
    f"{timestamp}.log"
)

print(f"The information from this audit will be logged in {log_file}.")
print()

#Configure the logging file
logging.basicConfig(
    filename=log_file,
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

#Create time variables and log information
script_start_datetime = datetime.datetime.now()
script_start_time = time.time()

logging.info(
    f"Password Audit Logger started at {script_start_datetime}"
)

logging.info(
    f"Investigator's Name: "
    f"{investigator_first.title()} {investigator_last.title()}"
)

logging.info(
    f"Investigator's Organization: {organization}"
)

logging.info(
    f"Investigation Purpose: {investigation_purpose}"
)

#Log system information in a presentable format
ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)

logging.info(f"Operating System: {platform.system()}")
logging.info(f"OS Version: {platform.release()}")
logging.info(f"Processor: {platform.processor()}")
logging.info(f"Python Version: {platform.python_version()}")
logging.info(f"CPU Cores: {psutil.cpu_count()}")
logging.info(f"RAM in GB: {ram_gb}")
logging.info(f"Hostname: {socket.gethostname()}")

#Create the rainbow table populated with all 3, 4, and 5 character passwords using the character set abc123!
character_set = "abc123!"

for password_length in range(3, 6):
    for password_tuple in itertools.product(character_set, repeat=password_length):
        password = "".join(password_tuple)
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        rainbow_table[password_hash] = password

#Log the number of passwords created in a presentable format
logging.info(f"Number of passwords created: {len(rainbow_table)}")

#Display the usernames that will be checked in the audit in a presentable format
print("The following usernames will be checked in the audit:\n")

for username in evidence_hashes:
    print(f"- {username}")

print()

#Display a message in a presentable format of the number of values in the rainbow table
print(
    f"Passwords will be tested against "
    f"{len(rainbow_table)} generated passwords in the rainbow table."
)

print()

#Search the rainbow table for each evidence hash
for username, password_hash in evidence_hashes.items():

    if password_hash in rainbow_table:

        cracked_password = rainbow_table.get(password_hash)

        investigation_results[username] = {
            "Username": username,
            "Password Hash": password_hash,
            "Status": "Cracked Password",
            "Cracked Password": cracked_password,
            "Recommendation": "Require password reset and user awareness training."
        }

        logging.warning(
            f"Password for {username} was found in rainbow table."
        )

    else:

        investigation_results[username] = {
            "Username": username,
            "Password Hash": password_hash,
            "Status": "Uncracked",
            "Cracked Password": "N/A",
            "Recommendation": "Password was not found in the limited rainbow table."
        }

        logging.info(
            f"Password for {username} was not found in rainbow table."
        )

#Set the default of cracked and uncracked to 0 in result_counts
result_counts.setdefault("Cracked Password", 0)
result_counts.setdefault("Uncracked", 0)

#Populate the result_counts dictionary to keep track of the number cracked and uncracked
for result in investigation_results.values():

    status = result["Status"]

    result_counts[status] += 1

#Is the number of cracked passwords critical
if result_counts["Cracked Password"] > 3:
    logging.critical("Number of cracked passwords is above threshold!")
else:
    logging.info("Number of cracked passwords is below threshold.")

#Display findings in a PrettyTable
findings_table = PrettyTable()
findings_table.title = f"Password Audit for {len(evidence_hashes)} Users"
findings_table.field_names = [
    "Username",
    "Hash Preview",
    "Status",
    "Cracked Password",
    "Recommendation"
]

findings_table.align = "l"

for username, result in investigation_results.items():
    findings_table.add_row([
        result["Username"],
        result["Password Hash"],
        result["Status"],
        result["Cracked Password"],
        result["Recommendation"]
    ])

print(findings_table.get_string(sortby="Status"))
print()

#Set defaults of pw counts
for length in range(3, 6):
    pw_counts.setdefault(length, 0)

#Count the number of passwords for each length
for password in rainbow_table.values():
    pw_counts[len(password)] += 1

#Create a PrettyTable and Display the information about the generated passwords
candidate_table = PrettyTable()
candidate_table.title = (
    f"Password Candidate Information for {len(rainbow_table)} Passwords"
)
candidate_table.field_names = [
    "Password Length",
    "Character Set Size",
    "Total Candidates"
]

for length, count in pw_counts.items():
    candidate_table.add_row([
        length,
        len(character_set),
        count
    ])

print(candidate_table)
print()

#Determine the runtime of the script
script_end_time = time.time()
elapsed_time = script_end_time - script_start_time
readable_runtime = str(datetime.timedelta(seconds=elapsed_time))

logging.info(f"Time taken to complete the test: {readable_runtime}")

#Create amd Display the Summary PrettyTable
summary_table = PrettyTable()
summary_table.title = f"Final Summary for {len(evidence_hashes)} User Accounts"
summary_table.field_names = ["Description", "Details"]
summary_table.align = "l"
summary_table.align["Details"] = "r"

summary_table.add_row(["Total Number of Rainbow Table Entries", len(rainbow_table)])
summary_table.add_row(["Evidence Hashes Checked", len(evidence_hashes)])
summary_table.add_row(["Cracked Account Passwords", result_counts["Cracked Password"]])
summary_table.add_row(["Uncracked Account Passwords", result_counts["Uncracked"]])
summary_table.add_row(["Log File Created", log_file])
summary_table.add_row(["Elapsed Time", readable_runtime])

print(summary_table)












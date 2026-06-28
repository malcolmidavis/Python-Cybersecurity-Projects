#Script: Cybersecurity File Inventory and Integrity Report
#Purpose: Analyze directory content and perform tasks on files

#Import Python Standard Libraries
from pathlib import Path
import hashlib
import time

#Import Third-Party Libraries
from prettytable import PrettyTable

#Variable Declarations
file_count = 0
directory_count = 0
processed_entries = 0

# ***** Main Program *****
#Display Current Working Directory to the User
current_directory = Path.cwd()
print(f"Current directory: {current_directory}")

#Display the Directories that are in the Current Working Directory
print("\nAvailable Directories:")
for item in current_directory.iterdir():
    if item.is_dir():
        print(item.name)

#Have the user enter in a valid directory to scan, use a while
#loop to ensure that they enter a valid directory.
while True:
    directory_name = input("\nEnter the directory you want to scan: ")
    selected_directory = current_directory / directory_name

    if selected_directory.exists() and selected_directory.is_dir():
        break
    else:
        print("invalid directory. Please enter a valid directory name.")

#Create a Pretty Table with the supplied headings, a title, and left aligned
table = PrettyTable()
table.title = f"File information for {selected_directory.name}"
table.field_names = [
    "File Name",
    "Type",
    "Extension",
    "Size in Bytes",
    "Modifies Time",
    "Accessed Time",
    "Created Time",
    "SHA-256 Hash",
]
table.align = "l"

#Create a text report file
report_file = Path("DavisAssignment4Report.txt")

#Process the files and folders within the user selected directory
rows = []

for item in selected_directory.iterdir():
    item_stat = item.stat()

    file_name = item.name
    size = item_stat.st_size
    modified_time = time.ctime(item_stat.st_mtime)
    accessed_time = time.ctime(item_stat.st_atime)
    created_time = time.ctime(item_stat.st_ctime)

    if item.is_file():
        file_count += 1
        item_type = "File"
        extension = item.suffix

        with open(item, "rb") as file:
            file_data = file.read()
            sha256_hash = hashlib.sha256(file_data).hexdigest()

    elif item.is_dir():
        directory_count += 1
        item_type = "Directory"
        extension = ""
        sha256_hash = "N/A"

    rows.append( [
        file_name,
        item_type,
        extension,
        size,
        modified_time,
        accessed_time,
        created_time,
        sha256_hash,
    ])

#Display PrettyTable sorted by Type and that File comes before Directory
rows.sort(key=lambda row: (0 if row [1] == "File" else 1, row [0]. lower()))

for row in rows:
    table.add_row(row)

print()
print(table)

#Open the report text file for writing and write the PrettyTable to the text file
with open(report_file, "w") as file:
    file.write(str(table))

#Calculate the processed entries and display a summary
processed_entries = file_count + directory_count

print()
print(" Items Processed Report ".center(40, "*"))
print(f"Files Processed: {file_count}")
print(f"Directories Processed: {directory_count}")
print(f"Processed Entries: {processed_entries}")
print(f"Report File Created: {report_file}")














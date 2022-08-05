# StoneGate Policy convert

Convert StoneGate firewall rules from XML format to readable CSV format

## Why should need convert to CSV form?

"XML format" everyone should understand this format, but when StoneGate Firewall has exported the firewall policy or whatever. The output file from StoneGate is an XML file and inside of this file is LXML format, which is Element Tree (ETree). It means the output file from the StoneGate XML file is obfuscated, and hard to read each firewall policy rule. That's why I have to parse from ETree and save it into the CSV. However, CSV (.csv) form is readable on every PC/Laptop that already has a Microsoft Excel program on it

## How to read file and parse the lxml format?

Python 3 and beautifulsoup are capable to read and parse "LXML", "XML", "HTML", and even broken "HTML" format, it can read these format too.
<br>
For more detail you can read this link below.<br>
![Beautifulsoup](https://lxml.de/elementsoup.html)

## Requirements

- Python 3 or Jupyter notebook with Anaconda
- python packge
  - beautifulsoup
  - pandas 
- Microsoft Excel

## How does my code work?

My code is working on Python or **J**u**py**te**r** (**Julia**, **Python**, **R**) Notebook (.ipynb) so it means this code can run on python environment python

## Structer of code

```python
import bs4
import pandas as pd

# Global params
data = []

class FW_Inspection:
    def inspection_entry(self):
    def global_inspection_entry(self):

class Firewall_Policy:
    def access_entry(self):
    def nat_entry(self):

class FW_sub_policy:
    def FW_Sub_Policy(data):

if __name__ == '__main__':
    with open("put_xml_file_and_path_here","r",encoding='utf-8',errors='ignore') as file:
        content = file.readlines()
        data = "".join(content)
        bs = bs4.BeautifulSoup(data, "lxml-xml")
    
    # To Run this code, uncomment this function below
    # FW_Inspection.inspection_entry(bs)
    # FW_Inspection.global_inspection_entry(bs)
    # Firewall_Policy.access_entry(bs)
    # Firewall_Policy.nat_entry(bs)
    # FW_sub_policy.FW_Sub_Policy(bs)
```

### inspection_entry & global_inspection_entry

**First class in my code**, is looking firewall inspection policy rule in **inspection_entry** and **global_inspection_entry** (if available) which focuses on below,

```md
- tag
- is_disabled
  - rule_entry
    - sources
      - each source
    - destinations
      - each destination
    - action
```

After listing each rule, we will append to each list then packed into dataframe, and export to csv file after finished.<br>


**Second class in my code**, is looking firewall policy, which contained **access_entry** and **nat_entry** but in **nat_entry** function is more difficult which will describe below

### Access Entry

```json
- fw_policy : {"name":"firewall_site"}
  - access_entry
    - rule_entry
    - tag
    - is_disabled
    - sources
      - each source
    - destinations
      - each destination
    - services
      - each service
    - action

```

### Nat Entry

```json
- fw_policy : {"name":"firewall_site"}
  - access_entry
    - rule_entry
    - tag
    - is_disabled
    - sources
      - each source
    - destinations
      - each destination
    - services
      - each service
    - action
    - option
      - If Nat Source
        - if static NAT or Dynamic NAT
          - if static NAT
            - Old Static NAT
            - New Static NAT
          - else if Dynamic NAT
            - Dynamic NAT
        - else (NAT destination)
          - Old Static NAT
          - New Static NAT
```

The funciton is similar to the previous class, espescially focuses on Nat Source and NAT destination, whi secondsch need to verify data output with engineer after file is processed

## Time Elapsed

|  Function | Time Elapsed  |
|:---:|:---:|
| inspection_entry | ~0.091 seconds |
| global_inspection_entry | ~0.11 seconds |
| access_entry | ~0.59 seconds |
| nat_entry | ~0.44 seconds |
| FW_Sub_Policy | ~0.18 seconds |
| main function<br>(read file & run each function) |  ~6.48 seconds |

## TODO

- Refactor code
- Clean code
- Code optimize
- Reduce line of code
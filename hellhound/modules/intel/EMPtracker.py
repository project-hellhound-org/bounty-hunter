import requests
from bs4 import BeautifulSoup
import re

NAME = "emp_tracker"
CATEGORY = "intel"
DESCRIPTION = "Extracts employee names & job titles from Team/About pages to generate usernames"

def clean_name(name):
    # Remove titles like Mr., Mrs., Dr.
    name = re.sub(r"(Mr|Mrs|Ms|Dr|Prof)\.\s+", "", name)
    # Remove extra whitespace
    return " ".join(name.split())

def generate_username(name, style="firstlast"):
    first, last = "", ""
    parts = name.split()
    if len(parts) >= 2:
        first = parts[0].lower()
        last = parts[-1].lower()
    else:
        return name.lower()

    if style == "firstlast": return f"{first}.{last}"
    if style == "lastfirst": return f"{last}.{first}"
    if style == "firstinitial_last": return f"{first[0]}{last}"
    return f"{first}{last}"

def run(target, emit, options=None):
    emit.info(f"[*] Employee Tracker: Scanning for personnel at {target}")
    
    base_url = target if target.startswith("http") else f"http://{target}"
    
    # Keywords to find staff pages
    staff_keywords = ["about", "team", "staff", "our-people", "careers", "leadership"]
    
    employees = []
    
    try:
        # 1. Try to find links on the homepage that match keywords
        r = requests.get(base_url, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        
        potential_links = []
        for a in soup.find_all("a", href=True):
            href = a["href"].lower()
            if any(k in href for k in staff_keywords):
                potential_links.append(a["href"])

        # Dedupe links
        potential_links = list(set(potential_links))
        
        # 2. Crawl those links
        for link in potential_links[:5]: # Limit to 5 pages to save time
            full_url = link if link.startswith("http") else base_url + link
            try:
                emit.info(f"    [>] Checking: {full_url}")
                p_r = requests.get(full_url, timeout=8)
                p_soup = BeautifulSoup(p_r.text, "html.parser")
                
                # Heuristic: Find elements with classes like 'name', 'person', 'staff-name'
                # Fallback: Look for patterns of "Capitalized Capitalized" text
                # This regex looks for words starting with Capital letters, typically names
                text_content = p_soup.get_text()
                matches = re.findall(r'\b([A-Z][a-z]+ [A-Z][a-z]+(?: [A-Z][a-z]+)?)\b', text_content)
                
                for match in matches[:10]: # Limit per page
                    clean = clean_name(match)
                    # Basic filter to avoid generic words
                    if len(clean.split()) >= 2 and clean not in ["Home Page", "Contact Us", "Read More"]:
                        employees.append(clean)
                        
            except Exception:
                continue

    except Exception as e:
        return {"raw": "Failed to scan target", "signals": ["SCAN_ERROR"]}

    # 3. Dedupe and Format
    employees = list(set(employees))
    usernames = []
    for emp in employees:
        usernames.append({
            "name": emp,
            "user_email_guess": generate_username(emp) + "@example.com", # Placeholder domain
            "user_login_guess": generate_username(emp)
        })

    # 4. Output
    if employees:
        emit.success(f"[+] Found {len(employees)} potential employees.")
        for e in employees[:3]:
            emit.info(f"    -> {e}")
        return {
            "raw": f"Found {len(employees)} employee names.",
            "intel": {"employees": employees, "usernames": usernames},
            "signals": ["PERSONNEL_DISCOVERED"]
        }
    else:
        emit.info("[-] No employee names found via simple heuristics.")
        return {"raw": "No personnel data found", "signals": []}
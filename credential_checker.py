import requests
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

class EnhancedCredentialChecker:
    def __init__(self):
        self.leaklookup_key = "2d72ea4c1c51567f3135e844df4bca67"
        self.rapidapi_key = "dc1df80be9mshacda6491009c662p101212jsn7a6d8af07908"
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def check_credential(self, cred_type, credential):
        """Check credential and save structured report"""
        if not credential:
            print(f"❌ {cred_type.capitalize()} cannot be empty")
            return

        print(f"\nChecking {cred_type}: {credential}")
        
        report = {
            "scan_time": datetime.now().isoformat(),
            "credential_type": cred_type,
            "credential": credential if cred_type != "password" else "SHA1:" + hashlib.sha1(credential.encode()).hexdigest(),
            "results": {
                "local_breaches": [],
                "online_breaches": []
            }
        }

        # Check local breaches
        local_results = self._check_local_breaches(credential)
        report["results"]["local_breaches"] = local_results["breaches"]

        # Check online services
        online_results = self._check_online_services(credential, cred_type)
        report["results"]["online_breaches"] = self._format_online_results(online_results)

        # Save report
        self._save_report(report, cred_type)
        self._display_results(report)

    def check_password(self, password):
        """Check password and save structured report"""
        if len(password) < 4:
            print("❌ Password too short (minimum 4 characters)")
            return

        print("\nChecking password (hashed for security)...")
        
        report = {
            "scan_time": datetime.now().isoformat(),
            "credential_type": "password",
            "credential": "SHA1:" + hashlib.sha1(password.encode()).hexdigest(),
            "results": {
                "local_breaches": [],
                "hibp": {}
            }
        }

        # Check local breaches
        local_results = self._check_local_breaches(password)
        report["results"]["local_breaches"] = local_results["breaches"]

        # Check HIBP
        pwned, count = self._check_pwned_password(password)
        report["results"]["hibp"] = {
            "leaked": pwned,
            "leak_count": count
        }

        # Save report
        self._save_report(report, "password")
        self._display_password_results(report)

    def _check_local_breaches(self, credential):
        """Check against local breach files"""
        results = {"leaked": False, "breaches": []}
        breach_dir = os.path.join("breach_data")
        os.makedirs(breach_dir, exist_ok=True)
        
        for breach_file in Path(breach_dir).glob("*.txt"):
            try:
                with open(breach_file, 'r', encoding='utf-8', errors='ignore') as f:
                    if any(credential.lower() in line.lower() for line in f):
                        results["breaches"].append({
                            "breach_name": breach_file.stem.replace('_', ' ').title(),
                            "breach_file": str(breach_file.name)
                        })
                        results["leaked"] = True
            except Exception:
                continue
        return results

    def _check_online_services(self, credential, cred_type):
        """Check against online breach databases"""
        results = {}
        
        # LeakLookup API
        try:
            params = {
                "key": self.leaklookup_key,
                "type": cred_type,
                "query": credential
            }
            response = requests.get(
                "https://leak-lookup.com/api/search",
                params=params,
                timeout=10
            )
            results["leaklookup"] = response.json()
        except Exception as e:
            results["leaklookup"] = {"error": str(e)}

        # BreachDirectory API
        try:
            headers = {
                "X-RapidAPI-Key": self.rapidapi_key,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
            }
            response = requests.get(
                "https://breachdirectory.p.rapidapi.com/",
                headers=headers,
                params={"func": "auto", "term": credential},
                timeout=10
            )
            results["breachdirectory"] = response.json()
        except Exception as e:
            results["breachdirectory"] = {"error": str(e)}
            
        return results

    def _check_pwned_password(self, password):
        """Check password against HIBP's Pwned Passwords"""
        try:
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=10
            )
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        return True, int(line.split(':')[1])
                return False, 0
            return None, None
        except:
            return None, None

    def _format_online_results(self, results):
        """Format online results for JSON report"""
        formatted = []
        
        # LeakLookup results
        if "leaklookup" in results and results["leaklookup"].get("success"):
            for breach in results["leaklookup"].get("results", []):
                formatted.append({
                    "source": "LeakLookup",
                    "breach_name": breach.get("name", "Unknown"),
                    "date": breach.get("date", "Unknown"),
                    "description": breach.get("description", "")
                })
        
        # BreachDirectory results
        if "breachdirectory" in results and results["breachdirectory"].get("found"):
            for breach in results["breachdirectory"].get("result", []):
                formatted.append({
                    "source": "BreachDirectory",
                    "breach_name": breach.get("name", "Unknown"),
                    "date": breach.get("date", "Unknown").split("T")[0],
                    "sources": breach.get("sources", "")
                })
        
        return formatted

    def _save_report(self, report, cred_type):
        """Save structured JSON report"""
        filename = f"credential_scan_{cred_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"\n📄 Report saved to: {filepath}")

    def _display_results(self, report):
        """Display results for email/username checks"""
        print(f"\n{'='*40}")
        print(f"🔍 {report['credential_type'].upper()} CHECK RESULTS")
        print('='*40)
        
        # Local breaches
        if report["results"]["local_breaches"]:
            print("\n❌ LOCAL BREACHES:")
            for breach in report["results"]["local_breaches"]:
                print(f"  - {breach['breach_name']}")

        # Online breaches
        if report["results"]["online_breaches"]:
            print("\n❌ ONLINE BREACHES:")
            for breach in report["results"]["online_breaches"]:
                print(f"  - {breach['breach_name']} ({breach['source']})")
        else:
            print("\n✅ No online breaches found")

        print('='*40 + '\n')

    def _display_password_results(self, report):
        """Display results for password checks"""
        print(f"\n{'='*40}")
        print("🔍 PASSWORD CHECK RESULTS")
        print('='*40)
        
        # Local breaches
        if report["results"]["local_breaches"]:
            print("\n❌ LOCAL BREACHES:")
            for breach in report["results"]["local_breaches"]:
                print(f"  - {breach['breach_name']}")

        # HIBP results
        hibp = report["results"]["hibp"]
        if hibp.get("leaked"):
            print(f"\n❌ HAVE I BEEN PWNED: Password leaked {hibp['leak_count']:,} times!")
        elif hibp.get("leaked") is False:
            print("\n✅ HAVE I BEEN PWNED: No leaks found")
        else:
            print("\n⚠️ HAVE I BEEN PWNED: Check failed")

        print('='*40 + '\n')
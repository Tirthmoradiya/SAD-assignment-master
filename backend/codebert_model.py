import torch
from transformers import RobertaTokenizer, RobertaModel
import numpy as np
from typing import Dict, List, Tuple, Optional, Union
import re
import os
from dataclasses import dataclass
from enum import Enum

class VulnerabilityType(Enum):
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

@dataclass
class Vulnerability:
    type: VulnerabilityType
    line_number: int
    code_snippet: str
    description: str
    severity: str
    recommendation: str

@dataclass
class CodeSummary:
    summary: str
    complexity: str
    maintainability: str
    key_functions: List[str]
    dependencies: List[str]

class CodeBERTAnalyzer:
    """
    A standalone class that uses CodeBERT for code understanding, summarization, and vulnerability detection.
    This class is not connected to any other files in the project.
    """
    
    def __init__(self, model_name: str = "microsoft/codebert-base"):
        """
        Initialize the CodeBERT model and tokenizer.
        
        Args:
            model_name: The name of the pre-trained model to use.
        """
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = RobertaTokenizer.from_pretrained(model_name)
        self.model = RobertaModel.from_pretrained(model_name).to(self.device)
        
        # Vulnerability patterns for different languages
        self.vulnerability_patterns = {
            "python": {
                VulnerabilityType.SQL_INJECTION: [
                    r"execute\s*\(\s*[\"'].*?\%.*?[\"']\s*\)",
                    r"cursor\.execute\s*\(\s*[\"'].*?\%.*?[\"']\s*\)",
                    r"db\.execute\s*\(\s*[\"'].*?\%.*?[\"']\s*\)",
                    r"connection\.execute\s*\(\s*[\"'].*?\%.*?[\"']\s*\)",
                    r"\.execute\s*\(\s*[\"'].*?f[\"'].*?[\"']\s*\)",
                ],
                VulnerabilityType.XSS: [
                    r"render_template\s*\(\s*[\"'].*?\{\{.*?\}\}.*?[\"']\s*\)",
                    r"render\s*\(\s*[\"'].*?\{\{.*?\}\}.*?[\"']\s*\)",
                    r"\.format\s*\(\s*.*?\)",
                    r"f[\"'].*?\{.*?\}.*?[\"']",
                ],
                VulnerabilityType.COMMAND_INJECTION: [
                    r"os\.system\s*\(\s*.*?\)",
                    r"subprocess\.call\s*\(\s*.*?\)",
                    r"subprocess\.Popen\s*\(\s*.*?\)",
                    r"\.run\s*\(\s*.*?shell=True.*?\)",
                ],
                VulnerabilityType.PATH_TRAVERSAL: [
                    r"open\s*\(\s*.*?\.\.\/.*?\)",
                    r"open\s*\(\s*.*?\.\.\\.*?\)",
                    r"\.read\s*\(\s*.*?\.\.\/.*?\)",
                    r"\.read\s*\(\s*.*?\.\.\\.*?\)",
                ],
                VulnerabilityType.INSECURE_DESERIALIZATION: [
                    r"pickle\.loads\s*\(\s*.*?\)",
                    r"yaml\.load\s*\(\s*.*?\)",
                    r"json\.loads\s*\(\s*.*?\)",
                ],
                VulnerabilityType.INSECURE_CRYPTO: [
                    r"md5\s*\(\s*.*?\)",
                    r"sha1\s*\(\s*.*?\)",
                    r"random\.random\s*\(\s*\)",
                    r"random\.randint\s*\(\s*\)",
                ],
                VulnerabilityType.HARDCODED_CREDENTIALS: [
                    r"password\s*=\s*[\"'].*?[\"']",
                    r"api_key\s*=\s*[\"'].*?[\"']",
                    r"secret\s*=\s*[\"'].*?[\"']",
                    r"token\s*=\s*[\"'].*?[\"']",
                ],
            },
            "javascript": {
                VulnerabilityType.SQL_INJECTION: [
                    r"execute\s*\(\s*[\"'].*?\${.*?}.*?[\"']\s*\)",
                    r"query\s*\(\s*[\"'].*?\${.*?}.*?[\"']\s*\)",
                    r"\.query\s*\(\s*[\"'].*?\${.*?}.*?[\"']\s*\)",
                ],
                VulnerabilityType.XSS: [
                    r"innerHTML\s*=\s*.*?",
                    r"document\.write\s*\(\s*.*?\)",
                    r"eval\s*\(\s*.*?\)",
                    r"\.append\s*\(\s*.*?\)",
                ],
                VulnerabilityType.COMMAND_INJECTION: [
                    r"child_process\.exec\s*\(\s*.*?\)",
                    r"child_process\.spawn\s*\(\s*.*?\)",
                    r"\.exec\s*\(\s*.*?\)",
                ],
                VulnerabilityType.PATH_TRAVERSAL: [
                    r"fs\.readFile\s*\(\s*.*?\.\.\/.*?\)",
                    r"fs\.readFile\s*\(\s*.*?\.\.\\.*?\)",
                    r"\.readFile\s*\(\s*.*?\.\.\/.*?\)",
                    r"\.readFile\s*\(\s*.*?\.\.\\.*?\)",
                ],
                VulnerabilityType.INSECURE_DESERIALIZATION: [
                    r"eval\s*\(\s*.*?\)",
                    r"JSON\.parse\s*\(\s*.*?\)",
                ],
                VulnerabilityType.INSECURE_CRYPTO: [
                    r"crypto\.createHash\s*\(\s*[\"']md5[\"']\s*\)",
                    r"crypto\.createHash\s*\(\s*[\"']sha1[\"']\s*\)",
                    r"Math\.random\s*\(\s*\)",
                ],
                VulnerabilityType.HARDCODED_CREDENTIALS: [
                    r"password\s*=\s*[\"'].*?[\"']",
                    r"apiKey\s*=\s*[\"'].*?[\"']",
                    r"secret\s*=\s*[\"'].*?[\"']",
                    r"token\s*=\s*[\"'].*?[\"']",
                ],
            }
        }
        
        # Code complexity patterns
        self.complexity_patterns = {
            "python": {
                "high_complexity": [
                    r"if\s+.*?:\s*\n\s*if\s+.*?:\s*\n\s*if\s+.*?:",
                    r"for\s+.*?:\s*\n\s*for\s+.*?:\s*\n\s*for\s+.*?:",
                    r"while\s+.*?:\s*\n\s*while\s+.*?:\s*\n\s*while\s+.*?:",
                    r"try:\s*\n\s*try:\s*\n\s*try:",
                ],
                "medium_complexity": [
                    r"if\s+.*?:\s*\n\s*if\s+.*?:",
                    r"for\s+.*?:\s*\n\s*for\s+.*?:",
                    r"while\s+.*?:\s*\n\s*while\s+.*?:",
                    r"try:\s*\n\s*try:",
                ],
            },
            "javascript": {
                "high_complexity": [
                    r"if\s*\(.*?\)\s*{\s*if\s*\(.*?\)\s*{\s*if\s*\(.*?\)\s*{",
                    r"for\s*\(.*?\)\s*{\s*for\s*\(.*?\)\s*{\s*for\s*\(.*?\)\s*{",
                    r"while\s*\(.*?\)\s*{\s*while\s*\(.*?\)\s*{\s*while\s*\(.*?\)\s*{",
                    r"try\s*{\s*try\s*{\s*try\s*{",
                ],
                "medium_complexity": [
                    r"if\s*\(.*?\)\s*{\s*if\s*\(.*?\)\s*{",
                    r"for\s*\(.*?\)\s*{\s*for\s*\(.*?\)\s*{",
                    r"while\s*\(.*?\)\s*{\s*while\s*\(.*?\)\s*{",
                    r"try\s*{\s*try\s*{",
                ],
            }
        }
    
    def analyze_code(self, code: str, language: str = "python") -> Dict:
        """
        Analyze code for understanding, summarization, and vulnerabilities.
        
        Args:
            code: The code to analyze.
            language: The programming language of the code (python or javascript).
            
        Returns:
            A dictionary containing the analysis results.
        """
        # Ensure language is lowercase
        language = language.lower()
        
        # Get code understanding
        understanding = self._get_code_understanding(code)
        
        # Get code summarization
        summary = self._get_code_summarization(code, language)
        
        # Get vulnerability detection
        vulnerabilities = self._detect_vulnerabilities(code, language)
        
        return {
            "understanding": understanding,
            "summary": summary,
            "vulnerabilities": vulnerabilities
        }
    
    def _get_code_understanding(self, code: str) -> Dict:
        """
        Get a deep understanding of the code using CodeBERT.
        
        Args:
            code: The code to understand.
            
        Returns:
            A dictionary containing the code understanding.
        """
        # Tokenize the code
        inputs = self.tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Get the model outputs
        with torch.no_grad():
            outputs = self.model(**inputs)
        
        # Get the embeddings
        embeddings = outputs.last_hidden_state.mean(dim=1).cpu().numpy()
        
        # Get the attention weights
        attention_weights = outputs.attentions[-1].mean(dim=1).mean(dim=1).cpu().numpy()
        
        # Get the token importance
        token_importance = attention_weights[0]
        
        # Get the tokenized code
        tokenized_code = self.tokenizer.convert_ids_to_tokens(inputs["input_ids"][0].cpu().numpy())
        
        # Get the important tokens
        important_tokens = []
        for i, importance in enumerate(token_importance):
            if importance > 0.1 and i < len(tokenized_code):
                important_tokens.append(tokenized_code[i])
        
        # Get the code structure
        code_structure = self._analyze_code_structure(code)
        
        return {
            "embeddings": embeddings.tolist(),
            "important_tokens": important_tokens,
            "code_structure": code_structure
        }
    
    def _analyze_code_structure(self, code: str) -> Dict:
        """
        Analyze the structure of the code.
        
        Args:
            code: The code to analyze.
            
        Returns:
            A dictionary containing the code structure.
        """
        # Split the code into lines
        lines = code.split("\n")
        
        # Count the number of lines
        num_lines = len(lines)
        
        # Count the number of functions
        functions = re.findall(r"def\s+\w+\s*\(.*?\):", code)
        num_functions = len(functions)
        
        # Count the number of classes
        classes = re.findall(r"class\s+\w+\s*:", code)
        num_classes = len(classes)
        
        # Count the number of imports
        imports = re.findall(r"import\s+.*", code)
        num_imports = len(imports)
        
        # Count the number of comments
        comments = re.findall(r"#.*", code)
        num_comments = len(comments)
        
        return {
            "num_lines": num_lines,
            "num_functions": num_functions,
            "num_classes": num_classes,
            "num_imports": num_imports,
            "num_comments": num_comments,
            "functions": functions,
            "classes": classes,
            "imports": imports
        }
    
    def _get_code_summarization(self, code: str, language: str) -> CodeSummary:
        """
        Get a summary of the code.
        
        Args:
            code: The code to summarize.
            language: The programming language of the code.
            
        Returns:
            A CodeSummary object containing the summary.
        """
        # Tokenize the code
        inputs = self.tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Get the model outputs
        with torch.no_grad():
            outputs = self.model(**inputs)
        
        # Get the embeddings
        embeddings = outputs.last_hidden_state.mean(dim=1).cpu().numpy()
        
        # Get the code complexity
        complexity = self._get_code_complexity(code, language)
        
        # Get the maintainability
        maintainability = self._get_code_maintainability(code)
        
        # Get the key functions
        key_functions = self._get_key_functions(code, language)
        
        # Get the dependencies
        dependencies = self._get_dependencies(code, language)
        
        # Generate a summary
        summary = self._generate_summary(embeddings, complexity, maintainability, key_functions, dependencies)
        
        return CodeSummary(
            summary=summary,
            complexity=complexity,
            maintainability=maintainability,
            key_functions=key_functions,
            dependencies=dependencies
        )
    
    def _get_code_complexity(self, code: str, language: str) -> str:
        """
        Get the complexity of the code.
        
        Args:
            code: The code to analyze.
            language: The programming language of the code.
            
        Returns:
            A string indicating the complexity of the code.
        """
        # Check for high complexity patterns
        for pattern in self.complexity_patterns.get(language, {}).get("high_complexity", []):
            if re.search(pattern, code, re.MULTILINE | re.DOTALL):
                return "High"
        
        # Check for medium complexity patterns
        for pattern in self.complexity_patterns.get(language, {}).get("medium_complexity", []):
            if re.search(pattern, code, re.MULTILINE | re.DOTALL):
                return "Medium"
        
        return "Low"
    
    def _get_code_maintainability(self, code: str) -> str:
        """
        Get the maintainability of the code.
        
        Args:
            code: The code to analyze.
            
        Returns:
            A string indicating the maintainability of the code.
        """
        # Count the number of lines
        num_lines = len(code.split("\n"))
        
        # Count the number of functions
        num_functions = len(re.findall(r"def\s+\w+\s*\(.*?\):", code))
        
        # Count the number of comments
        num_comments = len(re.findall(r"#.*", code))
        
        # Calculate the maintainability index
        if num_lines == 0:
            return "Unknown"
        
        comment_ratio = num_comments / num_lines
        
        if comment_ratio < 0.1:
            return "Low"
        elif comment_ratio < 0.2:
            return "Medium"
        else:
            return "High"
    
    def _get_key_functions(self, code: str, language: str) -> List[str]:
        """
        Get the key functions in the code.
        
        Args:
            code: The code to analyze.
            language: The programming language of the code.
            
        Returns:
            A list of key functions.
        """
        if language == "python":
            # Get all functions
            functions = re.findall(r"def\s+(\w+)\s*\(.*?\):", code)
            
            # Get all function calls
            function_calls = re.findall(r"(\w+)\s*\(.*?\)", code)
            
            # Count the occurrences of each function call
            function_counts = {}
            for func in function_calls:
                if func in functions:
                    function_counts[func] = function_counts.get(func, 0) + 1
            
            # Sort the functions by the number of calls
            sorted_functions = sorted(function_counts.items(), key=lambda x: x[1], reverse=True)
            
            # Get the top 5 functions
            return [func for func, _ in sorted_functions[:5]]
        
        elif language == "javascript":
            # Get all functions
            functions = re.findall(r"function\s+(\w+)\s*\(.*?\)\s*{", code)
            
            # Get all function calls
            function_calls = re.findall(r"(\w+)\s*\(.*?\)", code)
            
            # Count the occurrences of each function call
            function_counts = {}
            for func in function_calls:
                if func in functions:
                    function_counts[func] = function_counts.get(func, 0) + 1
            
            # Sort the functions by the number of calls
            sorted_functions = sorted(function_counts.items(), key=lambda x: x[1], reverse=True)
            
            # Get the top 5 functions
            return [func for func, _ in sorted_functions[:5]]
        
        return []
    
    def _get_dependencies(self, code: str, language: str) -> List[str]:
        """
        Get the dependencies in the code.
        
        Args:
            code: The code to analyze.
            language: The programming language of the code.
            
        Returns:
            A list of dependencies.
        """
        if language == "python":
            # Get all imports
            imports = re.findall(r"import\s+(.*)", code)
            
            # Get all from imports
            from_imports = re.findall(r"from\s+(.*?)\s+import\s+.*", code)
            
            # Combine the imports
            all_imports = imports + from_imports
            
            # Clean the imports
            cleaned_imports = []
            for imp in all_imports:
                # Remove the as part
                imp = re.sub(r"\s+as\s+.*", "", imp)
                
                # Remove the from part
                imp = re.sub(r"from\s+", "", imp)
                
                # Add the import to the list
                cleaned_imports.append(imp)
            
            return cleaned_imports
        
        elif language == "javascript":
            # Get all requires
            requires = re.findall(r"require\s*\(\s*[\"'](.*?)[\"']\s*\)", code)
            
            # Get all imports
            imports = re.findall(r"import\s+.*?\s+from\s+[\"'](.*?)[\"']", code)
            
            # Combine the imports
            all_imports = requires + imports
            
            return all_imports
        
        return []
    
    def _generate_summary(self, embeddings, complexity, maintainability, key_functions, dependencies) -> str:
        """
        Generate a summary of the code.
        
        Args:
            embeddings: The embeddings of the code.
            complexity: The complexity of the code.
            maintainability: The maintainability of the code.
            key_functions: The key functions in the code.
            dependencies: The dependencies in the code.
            
        Returns:
            A string containing the summary.
        """
        # Generate a summary based on the embeddings, complexity, maintainability, key functions, and dependencies
        summary = f"This code has {complexity} complexity and {maintainability} maintainability. "
        
        if key_functions:
            summary += f"The key functions are {', '.join(key_functions)}. "
        
        if dependencies:
            summary += f"The dependencies are {', '.join(dependencies)}. "
        
        return summary
    
    def _detect_vulnerabilities(self, code: str, language: str) -> List[Vulnerability]:
        """
        Detect vulnerabilities in the code.
        
        Args:
            code: The code to analyze.
            language: The programming language of the code.
            
        Returns:
            A list of Vulnerability objects.
        """
        vulnerabilities = []
        
        # Split the code into lines
        lines = code.split("\n")
        
        # Check for vulnerabilities
        for vuln_type, patterns in self.vulnerability_patterns.get(language, {}).items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.MULTILINE | re.DOTALL)
                for match in matches:
                    # Get the line number
                    line_number = code[:match.start()].count("\n") + 1
                    
                    # Get the code snippet
                    start_line = max(0, line_number - 2)
                    end_line = min(len(lines), line_number + 1)
                    code_snippet = "\n".join(lines[start_line:end_line])
                    
                    # Get the description
                    description = self._get_vulnerability_description(vuln_type)
                    
                    # Get the severity
                    severity = self._get_vulnerability_severity(vuln_type)
                    
                    # Get the recommendation
                    recommendation = self._get_vulnerability_recommendation(vuln_type)
                    
                    # Create a Vulnerability object
                    vulnerability = Vulnerability(
                        type=vuln_type,
                        line_number=line_number,
                        code_snippet=code_snippet,
                        description=description,
                        severity=severity,
                        recommendation=recommendation
                    )
                    
                    # Add the vulnerability to the list
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_vulnerability_description(self, vuln_type: VulnerabilityType) -> str:
        """
        Get the description of a vulnerability.
        
        Args:
            vuln_type: The type of vulnerability.
            
        Returns:
            A string containing the description.
        """
        descriptions = {
            VulnerabilityType.SQL_INJECTION: "SQL injection is a code injection technique used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution.",
            VulnerabilityType.XSS: "Cross-site scripting (XSS) is a type of security vulnerability typically found in web applications. XSS attacks enable attackers to inject client-side scripts into web pages viewed by other users.",
            VulnerabilityType.COMMAND_INJECTION: "Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application.",
            VulnerabilityType.PATH_TRAVERSAL: "Path traversal (also known as directory traversal) is a web security vulnerability that allows an attacker to access files and directories that are stored outside the web root folder.",
            VulnerabilityType.INSECURE_DESERIALIZATION: "Insecure deserialization is a vulnerability that occurs when untrusted data is used to instantiate an object, which can lead to arbitrary code execution.",
            VulnerabilityType.INSECURE_CRYPTO: "Insecure cryptography refers to the use of weak cryptographic algorithms or improper implementation of cryptographic functions.",
            VulnerabilityType.HARDCODED_CREDENTIALS: "Hardcoded credentials are security credentials (usernames, passwords, API keys, etc.) that are embedded directly in the source code.",
            VulnerabilityType.INSECURE_RANDOM: "Insecure random number generation refers to the use of weak random number generators that can be predicted by attackers.",
            VulnerabilityType.BUFFER_OVERFLOW: "Buffer overflow is a vulnerability that occurs when a program writes more data to a buffer than it can hold, causing adjacent memory locations to be overwritten.",
            VulnerabilityType.FORMAT_STRING: "Format string vulnerabilities occur when an application passes user-controlled input to a function that uses format strings without proper validation.",
            VulnerabilityType.INSECURE_DEFAULT: "Insecure default configuration refers to the use of default settings that are not secure and can be exploited by attackers.",
            VulnerabilityType.CSRF: "Cross-site request forgery (CSRF) is an attack that forces end users to perform actions that they do not intend to perform on a web application in which they are currently authenticated.",
            VulnerabilityType.OPEN_REDIRECT: "Open redirect is a vulnerability that occurs when an application redirects users to a URL specified in a parameter without proper validation.",
            VulnerabilityType.XXE: "XML External Entity (XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data.",
            VulnerabilityType.SSRF: "Server-side request forgery (SSRF) is a web security vulnerability that allows attackers to induce the server-side application to make requests to unintended locations.",
            VulnerabilityType.IDOR: "Insecure Direct Object Reference (IDOR) is a vulnerability that occurs when an application provides direct access to objects based on user-supplied input.",
            VulnerabilityType.BROKEN_AUTH: "Broken authentication refers to vulnerabilities in the authentication mechanisms of an application.",
            VulnerabilityType.SESSION_MANAGEMENT: "Insecure session management refers to vulnerabilities in the way an application manages user sessions.",
            VulnerabilityType.FILE_UPLOAD: "Insecure file upload refers to vulnerabilities in the way an application handles file uploads.",
            VulnerabilityType.INSECURE_DEPENDENCY: "Insecure dependency refers to the use of third-party libraries or components that have known vulnerabilities.",
        }
        
        return descriptions.get(vuln_type, "Unknown vulnerability type.")
    
    def _get_vulnerability_severity(self, vuln_type: VulnerabilityType) -> str:
        """
        Get the severity of a vulnerability.
        
        Args:
            vuln_type: The type of vulnerability.
            
        Returns:
            A string containing the severity.
        """
        high_severity = [
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.INSECURE_DESERIALIZATION,
            VulnerabilityType.BUFFER_OVERFLOW,
            VulnerabilityType.XXE,
            VulnerabilityType.SSRF,
        ]
        
        medium_severity = [
            VulnerabilityType.XSS,
            VulnerabilityType.PATH_TRAVERSAL,
            VulnerabilityType.INSECURE_CRYPTO,
            VulnerabilityType.HARDCODED_CREDENTIALS,
            VulnerabilityType.FORMAT_STRING,
            VulnerabilityType.CSRF,
            VulnerabilityType.IDOR,
            VulnerabilityType.BROKEN_AUTH,
        ]
        
        if vuln_type in high_severity:
            return "High"
        elif vuln_type in medium_severity:
            return "Medium"
        else:
            return "Low"
    
    def _get_vulnerability_recommendation(self, vuln_type: VulnerabilityType) -> str:
        """
        Get the recommendation for fixing a vulnerability.
        
        Args:
            vuln_type: The type of vulnerability.
            
        Returns:
            A string containing the recommendation.
        """
        recommendations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements to prevent SQL injection attacks.",
            VulnerabilityType.XSS: "Use proper output encoding and input validation to prevent XSS attacks.",
            VulnerabilityType.COMMAND_INJECTION: "Avoid using user input in command execution functions. If necessary, use whitelisting and proper input validation.",
            VulnerabilityType.PATH_TRAVERSAL: "Validate and sanitize file paths to prevent path traversal attacks.",
            VulnerabilityType.INSECURE_DESERIALIZATION: "Avoid deserializing untrusted data. If necessary, use a safe deserialization method and validate the data.",
            VulnerabilityType.INSECURE_CRYPTO: "Use strong cryptographic algorithms and proper implementation of cryptographic functions.",
            VulnerabilityType.HARDCODED_CREDENTIALS: "Store credentials securely, such as in environment variables or a secure vault, not in the source code.",
            VulnerabilityType.INSECURE_RANDOM: "Use cryptographically secure random number generators, such as os.urandom() in Python or crypto.randomBytes() in Node.js.",
            VulnerabilityType.BUFFER_OVERFLOW: "Use safe string handling functions and proper bounds checking to prevent buffer overflows.",
            VulnerabilityType.FORMAT_STRING: "Validate user input before passing it to functions that use format strings.",
            VulnerabilityType.INSECURE_DEFAULT: "Change default settings to secure values and document the changes.",
            VulnerabilityType.CSRF: "Use CSRF tokens to prevent CSRF attacks.",
            VulnerabilityType.OPEN_REDIRECT: "Validate and whitelist redirect URLs to prevent open redirect attacks.",
            VulnerabilityType.XXE: "Disable XML external entity processing to prevent XXE attacks.",
            VulnerabilityType.SSRF: "Validate and whitelist URLs to prevent SSRF attacks.",
            VulnerabilityType.IDOR: "Implement proper access controls to prevent IDOR attacks.",
            VulnerabilityType.BROKEN_AUTH: "Implement secure authentication mechanisms, such as multi-factor authentication and proper session management.",
            VulnerabilityType.SESSION_MANAGEMENT: "Implement secure session management, such as session timeout, secure session storage, and proper session validation.",
            VulnerabilityType.FILE_UPLOAD: "Validate file uploads, such as file type, size, and content, to prevent malicious file uploads.",
            VulnerabilityType.INSECURE_DEPENDENCY: "Keep dependencies up to date and use dependency scanning tools to identify and fix vulnerabilities.",
        }
        
        return recommendations.get(vuln_type, "No recommendation available for this vulnerability type.")


# Example usage
if __name__ == "__main__":
    # Create an instance of the CodeBERTAnalyzer
    analyzer = CodeBERTAnalyzer()
    
    # Example Python code
    python_code = """
import os
import sqlite3
import pickle

def get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    # Vulnerable to command injection
    os.system(f"echo {user_id}")
    
    # Vulnerable to insecure deserialization
    data = pickle.loads(user_id)
    
    # Vulnerable to hardcoded credentials
    password = "mysecretpassword"
    
    return cursor.fetchall()
    """
    
    # Analyze the Python code
    python_results = analyzer.analyze_code(python_code, "python")
    
    # Print the results
    print("Python Code Analysis:")
    print("=====================")
    print("Code Understanding:")
    print(f"Number of important tokens: {len(python_results['understanding']['important_tokens'])}")
    print(f"Code structure: {python_results['understanding']['code_structure']}")
    print("\nCode Summary:")
    print(f"Summary: {python_results['summary'].summary}")
    print(f"Complexity: {python_results['summary'].complexity}")
    print(f"Maintainability: {python_results['summary'].maintainability}")
    print(f"Key functions: {python_results['summary'].key_functions}")
    print(f"Dependencies: {python_results['summary'].dependencies}")
    print("\nVulnerabilities:")
    for vuln in python_results['vulnerabilities']:
        print(f"Type: {vuln.type.value}")
        print(f"Line number: {vuln.line_number}")
        print(f"Description: {vuln.description}")
        print(f"Severity: {vuln.severity}")
        print(f"Recommendation: {vuln.recommendation}")
        print("---")
    
    # Example JavaScript code
    javascript_code = """
const express = require('express');
const app = express();
const mysql = require('mysql');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'mydb'
});

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  
  // Vulnerable to SQL injection
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.send(results);
  });
  
  // Vulnerable to XSS
  res.send(`<h1>Welcome ${userId}</h1>`);
  
  // Vulnerable to command injection
  const { exec } = require('child_process');
  exec(`echo ${userId}`);
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
    """
    
    # Analyze the JavaScript code
    javascript_results = analyzer.analyze_code(javascript_code, "javascript")
    
    # Print the results
    print("\nJavaScript Code Analysis:")
    print("=========================")
    print("Code Understanding:")
    print(f"Number of important tokens: {len(javascript_results['understanding']['important_tokens'])}")
    print(f"Code structure: {javascript_results['understanding']['code_structure']}")
    print("\nCode Summary:")
    print(f"Summary: {javascript_results['summary'].summary}")
    print(f"Complexity: {javascript_results['summary'].complexity}")
    print(f"Maintainability: {javascript_results['summary'].maintainability}")
    print(f"Key functions: {javascript_results['summary'].key_functions}")
    print(f"Dependencies: {javascript_results['summary'].dependencies}")
    print("\nVulnerabilities:")
    for vuln in javascript_results['vulnerabilities']:
        print(f"Type: {vuln.type.value}")
        print(f"Line number: {vuln.line_number}")
        print(f"Description: {vuln.description}")
        print(f"Severity: {vuln.severity}")
        print(f"Recommendation: {vuln.recommendation}")
        print("---") 
        
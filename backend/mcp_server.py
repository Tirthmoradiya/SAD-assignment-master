import asyncio
import httpx
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
import os
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor

class VulnerabilityResult(BaseModel):
    source: str
    severity: str
    description: str
    location: str
    recommendation: str
    confidence: float

class MCPAnalysisRequest(BaseModel):
    code: str
    language: str = "python"
    file_path: Optional[str] = None
    repository_url: Optional[str] = None

class MCPAnalysisResponse(BaseModel):
    scan_id: str
    status: str
    results: List[VulnerabilityResult]
    summary: Dict[str, int]

class MCPBaseServer:
    def _init_(self, name: str, port: int):
        self.name = name
        self.port = port
        self.app = FastAPI()
        self.setup_routes()

    def setup_routes(self):
        @self.app.post("/analyze")
        async def analyze(request: MCPAnalysisRequest):
            try:
                results = await self.analyze_code(request)
                return MCPAnalysisResponse(
                    scan_id=f"{self.name}-{int(time.time())}",
                    status="completed",
                    results=results,
                    summary=self.generate_summary(results)
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

    async def analyze_code(self, request: MCPAnalysisRequest) -> List[VulnerabilityResult]:
        raise NotImplementedError

    def generate_summary(self, results: List[VulnerabilityResult]) -> Dict[str, int]:
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        for result in results:
            summary[result.severity.lower()] += 1
        return summary

class StaticAnalysisServer(MCPBaseServer):
    def _init_(self):
        super()._init_("static_analysis", 8001)

    async def analyze_code(self, request: MCPAnalysisRequest) -> List[VulnerabilityResult]:
        results = []
        
        # Pattern-based analysis
        patterns = {
            "critical": [
                (r'eval\(', "Use of eval() can lead to code injection"),
                (r'exec\(', "Use of exec() can lead to code injection"),
                (r'os\.system\(', "Use of os.system() can lead to command injection"),
                (r'pickle\.loads\(', "Use of pickle.loads() can lead to code injection"),
                (r'password\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded password detected"),
                (r'api_key\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded API key detected")
            ],
            "high": [
                (r'open\([^,]+,\s*[\'"]w[\'"]\)', "Unsafe file write operation"),
                (r'open\([^,]+,\s*[\'"]a[\'"]\)', "Unsafe file append operation"),
                (r'SELECT.FROM.*WHERE.\$\{', "Potential SQL injection"),
                (r'innerHTML\s*=\s*[\'"]', "Potential XSS vulnerability")
            ]
        }

        for severity, pattern_list in patterns.items():
            for pattern, description in pattern_list:
                matches = self.find_pattern_matches(request.code, pattern)
                for line_number in matches:
                    results.append(VulnerabilityResult(
                        source="static_analysis",
                        severity=severity,
                        description=description,
                        location=f"Line {line_number}",
                        recommendation="Review and fix the identified security issue",
                        confidence=0.9
                    ))

        return results

    def find_pattern_matches(self, code: str, pattern: str) -> List[int]:
        import re
        matches = []
        for i, line in enumerate(code.split('\n')):
            if re.search(pattern, line):
                matches.append(i + 1)
        return matches

class DependencyAnalysisServer(MCPBaseServer):
    def _init_(self):
        super()._init_("dependency_analysis", 8002)

    async def analyze_code(self, request: MCPAnalysisRequest) -> List[VulnerabilityResult]:
        results = []

        vulnerable_dependencies = {
            "requests": {
                "version": "<2.31.0",
                "cve": "CVE-2023-32681",
                "description": "HTTP redirect vulnerability",
                "severity": "high"
            },
            "flask": {
                "version": "<2.3.0",
                "cve": "CVE-2023-30861",
                "description": "Request smuggling vulnerability",
                "severity": "critical"
            }
        }

        for package, details in vulnerable_dependencies.items():
            results.append(VulnerabilityResult(
                source="dependency_analysis",
                severity=details["severity"],
                description=f"{package} {details['version']}: {details['description']} ({details['cve']})",
                location=f"Dependency: {package}",
                recommendation=f"Upgrade {package} to the latest version",
                confidence=0.95
            ))

        return results

class CodeQualityServer(MCPBaseServer):
    def _init_(self):
        super()._init_("code_quality", 8003)

    async def analyze_code(self, request: MCPAnalysisRequest) -> List[VulnerabilityResult]:
        results = []
        
        # Analyze code complexity
        complexity_issues = self.analyze_complexity(request.code)
        results.extend(complexity_issues)

        # Analyze code duplication
        duplication_issues = self.analyze_duplication(request.code)
        results.extend(duplication_issues)

        return results

    def analyze_complexity(self, code: str) -> List[VulnerabilityResult]:
        results = []
        # Simple complexity analysis based on function length
        functions = self.extract_functions(code)
        for func_name, func_code in functions.items():
            lines = len(func_code.split('\n'))
            if lines > 50:
                results.append(VulnerabilityResult(
                    source="code_quality",
                    severity="medium",
                    description=f"Function '{func_name}' is too long ({lines} lines)",
                    location=f"Function: {func_name}",
                    recommendation="Consider breaking down the function into smaller, more manageable pieces",
                    confidence=0.8
                ))
        return results

    def analyze_duplication(self, code: str) -> List[VulnerabilityResult]:
        results = []
        # Simple duplication detection
        lines = code.split('\n')
        for i in range(len(lines) - 5):
            chunk = '\n'.join(lines[i:i+5])
            if code.count(chunk) > 1:
                results.append(VulnerabilityResult(
                    source="code_quality",
                    severity="low",
                    description="Code duplication detected",
                    location=f"Lines {i+1}-{i+5}",
                    recommendation="Consider extracting the duplicated code into a reusable function",
                    confidence=0.7
                ))
        return results

    def extract_functions(self, code: str) -> Dict[str, str]:
        # Simple function extraction for Python
        functions = {}
        current_function = None
        current_code = []
        indent_level = 0

        for line in code.split('\n'):
            if line.strip().startswith('def '):
                if current_function:
                    functions[current_function] = '\n'.join(current_code)
                current_function = line.strip().split('def ')[1].split('(')[0]
                current_code = [line]
                indent_level = len(line) - len(line.lstrip())
            elif current_function and line.strip():
                current_indent = len(line) - len(line.lstrip())
                if current_indent > indent_level:
                    current_code.append(line)
                else:
                    functions[current_function] = '\n'.join(current_code)
                    current_function = None
                    current_code = []

        if current_function:
            functions[current_function] = '\n'.join(current_code)

        return functions

class OWASPServer(MCPBaseServer):
    def _init_(self):
        super()._init_("owasp_analysis", 8004)

    async def analyze_code(self, request: MCPAnalysisRequest) -> List[VulnerabilityResult]:
        results = []
        
        # OWASP Top 10 vulnerability patterns
        owasp_patterns = {
            "critical": [
                (r'SQL.*injection', "Potential SQL Injection vulnerability"),
                (r'XSS.*vulnerability', "Potential Cross-Site Scripting (XSS) vulnerability"),
                (r'CSRF.*token', "Missing CSRF protection"),
                (r'password.*in.*plaintext', "Password stored in plaintext"),
                (r'JWT.*secret.*hardcoded', "Hardcoded JWT secret")
            ],
            "high": [
                (r'broken.*authentication', "Broken authentication pattern detected"),
                (r'sensitive.*data.*exposure', "Sensitive data exposure risk"),
                (r'XML.*external.*entity', "Potential XXE vulnerability"),
                (r'insecure.*deserialization', "Insecure deserialization detected")
            ],
            "medium": [
                (r'security.*misconfiguration', "Security misconfiguration detected"),
                (r'using.*components.*with.*known.*vulnerabilities', "Using components with known vulnerabilities"),
                (r'insufficient.*logging.*and.*monitoring', "Insufficient logging and monitoring")
            ]
        }

        for severity, pattern_list in owasp_patterns.items():
            for pattern, description in pattern_list:
                matches = self.find_pattern_matches(request.code, pattern)
                for line_number in matches:
                    results.append(VulnerabilityResult(
                        source="owasp_analysis",
                        severity=severity,
                        description=description,
                        location=f"Line {line_number}",
                        recommendation="Review OWASP Top 10 guidelines and implement security best practices",
                        confidence=0.85
                    ))

        return results

class WikipediaSecurityServer(MCPBaseServer):
    def _init_(self):
        super()._init_("wikipedia_security", 8005)
        self.security_terms = {
            "buffer_overflow": "A buffer overflow occurs when a program writes more data to a buffer than it can hold",
            "sql_injection": "SQL injection is a code injection technique that might destroy your database",
            "cross_site_scripting": "Cross-site scripting (XSS) is a type of security vulnerability",
            "csrf": "Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions",
            "authentication": "Authentication is the process of verifying who a user is"
        }

    async def analyze_code(self, request: MCPAnalysisRequest) -> List[VulnerabilityResult]:
        results = []
        
        # Search for security-related terms in the code
        for term, description in self.security_terms.items():
            pattern = term.replace('_', '.*')
            matches = self.find_pattern_matches(request.code, pattern)
            for line_number in matches:
                results.append(VulnerabilityResult(
                    source="wikipedia_security",
                    severity="medium",
                    description=f"Security concept detected: {description}",
                    location=f"Line {line_number}",
                    recommendation="Review security best practices for this concept",
                    confidence=0.75
                ))

        return results

class AICodeAnalyzerServer(MCPBaseServer):
    def _init_(self):
        super()._init_("ai_analyzer", 8006)

    async def analyze_code(self, request: MCPAnalysisRequest) -> List[VulnerabilityResult]:
        results = []
        
        # AI-based analysis patterns
        ai_patterns = {
            "critical": [
                (r'AI.*model.*injection', "Potential AI model injection vulnerability"),
                (r'prompt.*injection', "Potential prompt injection vulnerability"),
                (r'data.*poisoning', "Potential data poisoning vulnerability")
            ],
            "high": [
                (r'AI.*bias', "Potential AI bias in the implementation"),
                (r'model.*stealing', "Potential model stealing vulnerability"),
                (r'adversarial.*attack', "Potential adversarial attack vulnerability")
            ],
            "medium": [
                (r'AI.*ethics', "AI ethics consideration needed"),
                (r'explainability', "AI model explainability issue"),
                (r'fairness', "AI fairness consideration needed")
            ]
        }

        for severity, pattern_list in ai_patterns.items():
            for pattern, description in pattern_list:
                matches = self.find_pattern_matches(request.code, pattern)
                for line_number in matches:
                    results.append(VulnerabilityResult(
                        source="ai_analyzer",
                        severity=severity,
                        description=description,
                        location=f"Line {line_number}",
                        recommendation="Review AI security best practices and implement appropriate safeguards",
                        confidence=0.9
                    ))

        return results

class MCPCoordinator:
    def _init_(self):
        self.servers = {
            "static": StaticAnalysisServer(),
            "dependency": DependencyAnalysisServer(),
            "quality": CodeQualityServer(),
            "owasp": OWASPServer(),
            "wikipedia": WikipediaSecurityServer(),
            "ai": AICodeAnalyzerServer()
        }
        self.app = FastAPI()
        self.setup_routes()

    def setup_routes(self):
        @self.app.post("/analyze")
        async def analyze(request: MCPAnalysisRequest):
            try:
                results = await self.coordinate_analysis(request)
                return MCPAnalysisResponse(
                    scan_id=f"coordinated-{int(time.time())}",
                    status="completed",
                    results=results,
                    summary=self.generate_summary(results)
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

    async def coordinate_analysis(self, request: MCPAnalysisRequest) -> List[VulnerabilityResult]:
        all_results = []
        
        async with httpx.AsyncClient() as client:
            for server_name, server in self.servers.items():
                try:
                    response = await client.post(
                        f"http://localhost:{server.port}/analyze",
                        json=request.dict()
                    )
                    if response.status_code == 200:
                        server_results = response.json()["results"]
                        all_results.extend([
                            VulnerabilityResult(**result)
                            for result in server_results
                        ])
                except Exception as e:
                    print(f"Error from {server_name} server: {str(e)}")

        return all_results

    def generate_summary(self, results: List[VulnerabilityResult]) -> Dict[str, int]:
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        for result in results:
            summary[result.severity.lower()] += 1
        return summary

    async def start_servers(self):
        import uvicorn
        from threading import Thread

        def run_server(server, port):
            uvicorn.run(server.app, host="0.0.0.0", port=port)

        # Start each server in a separate thread
        threads = []
        for server_name, server in self.servers.items():
            thread = Thread(
                target=run_server,
                args=(server, server.port),
                daemon=True
            )
            threads.append(thread)
            thread.start()

        # Start the coordinator server
        uvicorn.run(self.app, host="0.0.0.0", port=8000)

if _name_ == "_main_":
    coordinator = MCPCoordinator()
    asyncio.run(coordinator.start_servers())
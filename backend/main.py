import shutil
import tempfile
import os
import git
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from github_utils import clone_repo, clean_github_url
from ai_analyzer import analyze_code
from dependency_scanner import parse_requirements, check_cve_vulnerabilities, check_dependencies
from typing import Optional, Dict, List
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import asyncio
from concurrent.futures import ThreadPoolExecutor
import time

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Get the absolute path to the frontend build directory
frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'build'))

# Mount the static files from React build if the directory exists
if os.path.exists(os.path.join(frontend_path, "static")):
    app.mount("/static", StaticFiles(directory=os.path.join(frontend_path, "static")), name="static")

# Store scan results
scan_results: Dict[str, dict] = {}

class ScanRequest(BaseModel):
    repo_url: Optional[str] = None
    code: Optional[str] = None
    check_dependencies: bool = True
    language: str = "python"  # Default to Python

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

@app.post("/api/scan", response_model=ScanResponse)
async def scan_repository(request: ScanRequest, background_tasks: BackgroundTasks):
    try:
        scan_id = str(hash(str(request.dict()) + str(time.time())))
        scan_results[scan_id] = {
            "status": "processing",
            "message": "Scan started",
            "progress": 0
        }
        
        background_tasks.add_task(process_scan, scan_id, request)
        
        return {
            "scan_id": scan_id,
            "status": "processing",
            "message": "Scan started successfully"
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to start scan: {str(e)}"}
        )

@app.get("/api/scan/{scan_id}")
async def get_scan_results(scan_id: str):
    if scan_id not in scan_results:
        return JSONResponse(
            status_code=404,
            content={"error": "Scan not found"}
        )
    
    result = scan_results[scan_id]
    if result["status"] == "completed":
        # Clean up the result after sending
        scan_results.pop(scan_id, None)
    
    return result

# Serve the React frontend for all other routes
@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    # First check if the frontend is built
    if not os.path.exists(frontend_path):
        return JSONResponse(
            status_code=404,
            content={"error": "Frontend not built. Please run 'npm run build' in the frontend directory."}
        )

    # For API routes, return 404
    if full_path.startswith("api/"):
        return JSONResponse(
            status_code=404,
            content={"error": "API endpoint not found"}
        )

    # Try to serve the requested file
    requested_file = os.path.join(frontend_path, full_path)
    if os.path.exists(requested_file) and not os.path.isdir(requested_file):
        return FileResponse(requested_file)

    # Default to serving index.html for client-side routing
    index_path = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    else:
        return JSONResponse(
            status_code=404,
            content={"error": "Frontend not built. Please run 'npm run build' in the frontend directory."}
        )

async def process_scan(scan_id: str, request: ScanRequest):
    try:
        scan_results[scan_id]["message"] = "Initializing scan..."
        scan_results[scan_id]["progress"] = 10

        if request.repo_url:
            try:
                clean_url = clean_github_url(request.repo_url)
                repo_path = clone_repo(clean_url)
                scan_results[scan_id]["message"] = "Repository cloned successfully"
                scan_results[scan_id]["progress"] = 30
            except Exception as e:
                scan_results[scan_id].update({
                    "status": "error",
                    "message": f"Failed to clone repository: {str(e)}",
                    "progress": 100
                })
                return
        else:
            repo_path = tempfile.mkdtemp()
            try:
                # Create file with appropriate extension based on language
                extension = ".py" if request.language == "python" else ".js"
                code_file = os.path.join(repo_path, f"code{extension}")
                with open(code_file, "w", encoding="utf-8") as f:
                    f.write(request.code)
                scan_results[scan_id]["message"] = "Code file created successfully"
                scan_results[scan_id]["progress"] = 30
            except Exception as e:
                scan_results[scan_id].update({
                    "status": "error",
                    "message": f"Failed to process code: {str(e)}",
                    "progress": 100
                })
                return

        try:
            # Analyze code in a separate thread
            with ThreadPoolExecutor() as executor:
                loop = asyncio.get_event_loop()
                code_analysis = await loop.run_in_executor(
                    executor, 
                    analyze_code, 
                    repo_path,
                    request.language
                )
            
            scan_results[scan_id]["message"] = "Code analysis completed"
            scan_results[scan_id]["progress"] = 60

            # Check dependencies if requested
            dependency_vulnerabilities = []
            if request.check_dependencies:
                try:
                    with ThreadPoolExecutor() as executor:
                        loop = asyncio.get_event_loop()
                        dependency_vulnerabilities = await loop.run_in_executor(
                            executor, 
                            check_dependencies, 
                            repo_path,
                            request.language
                        )
                except Exception as e:
                    print(f"Error checking dependencies: {str(e)}")
                    dependency_vulnerabilities = [{
                        "package": "error",
                        "version": "unknown",
                        "vulnerabilities": [{
                            "cve_id": "N/A",
                            "severity": "error",
                            "description": f"Failed to check dependencies: {str(e)}"
                        }]
                    }]

            scan_results[scan_id]["message"] = "Dependency check completed"
            scan_results[scan_id]["progress"] = 90

            # Calculate summary statistics
            total_vulnerabilities = sum(
                len(result.get("static_analysis", {}).get("vulnerabilities", []))
                for result in code_analysis
            )
            
            critical_vulnerabilities = sum(
                sum(1 for v in result.get("static_analysis", {}).get("vulnerabilities", [])
                    if v.get("severity", "").lower() == "critical")
                for result in code_analysis
            )
            
            high_vulnerabilities = sum(
                sum(1 for v in result.get("static_analysis", {}).get("vulnerabilities", [])
                    if v.get("severity", "").lower() == "high")
                for result in code_analysis
            )
            
            medium_vulnerabilities = sum(
                sum(1 for v in result.get("static_analysis", {}).get("vulnerabilities", [])
                    if v.get("severity", "").lower() == "medium")
                for result in code_analysis
            )
            
            low_vulnerabilities = sum(
                sum(1 for v in result.get("static_analysis", {}).get("vulnerabilities", [])
                    if v.get("severity", "").lower() == "low")
                for result in code_analysis
            )

            scan_results[scan_id].update({
                "status": "completed",
                "message": "Scan completed successfully",
                "progress": 100,
                "results": {
                    "code_analysis": code_analysis,
                    "dependency_vulnerabilities": dependency_vulnerabilities,
                    "summary": {
                        "total_files_analyzed": len(code_analysis),
                        "total_vulnerabilities": total_vulnerabilities,
                        "critical_vulnerabilities": critical_vulnerabilities,
                        "high_vulnerabilities": high_vulnerabilities,
                        "medium_vulnerabilities": medium_vulnerabilities,
                        "low_vulnerabilities": low_vulnerabilities
                    }
                }
            })

        except Exception as e:
            scan_results[scan_id].update({
                "status": "error",
                "message": f"Analysis failed: {str(e)}",
                "progress": 100
            })
        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(repo_path)
            except Exception as e:
                print(f"Error cleaning up temporary directory: {str(e)}")

    except Exception as e:
        scan_results[scan_id].update({
            "status": "error",
            "message": f"Unexpected error: {str(e)}",
            "progress": 100
        })
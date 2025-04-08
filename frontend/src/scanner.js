import React, { useState } from 'react';
import { 
  Box, 
  TextField, 
  Button, 
  Checkbox,
  FormControlLabel,
  Paper, 
  Typography,
  CircularProgress,
  Tabs,
  Tab,
  LinearProgress,
  Container,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Tooltip,
  Snackbar,
  Alert,
  Card,
  CardContent,
  CardActions
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import axios from 'axios';

const Scanner = () => {
  const [tab, setTab] = useState(0);
  const [repoUrl, setRepoUrl] = useState('');
  const [code, setCode] = useState('');
  const [checkDependencies, setCheckDependencies] = useState(true);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [scanId, setScanId] = useState(null);
  const [language, setLanguage] = useState('python');
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [correctedCode, setCorrectedCode] = useState({});

  const handleTabChange = (event, newValue) => {
    setTab(newValue);
    setResults(null);
    setError(null);
  };

  const handleLanguageChange = (event) => {
    setLanguage(event.target.value);
  };

  const handleScan = async () => {
    try {
      setLoading(true);
      setError(null);
      setResults(null);
      setScanProgress(0);
      setScanStatus('Initializing scan...');

      const response = await axios.post('/api/scan', {
        repo_url: tab === 0 ? repoUrl : null,
        code: tab === 1 ? code : null,
        check_dependencies: checkDependencies,
        language: language
      });

      if (response.data && response.data.scan_id) {
        setScanId(response.data.scan_id);
        pollScanResults(response.data.scan_id);
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      setError(error.response?.data?.error || 'An error occurred while scanning');
      setLoading(false);
    }
  };

  const pollScanResults = async (id) => {
    try {
      const response = await axios.get(`/api/scan/${id}`);
      const data = response.data;

      setScanProgress(data.progress || 0);
      setScanStatus(data.message || '');

      if (data.status === 'completed') {
        setResults(data.results);
        setLoading(false);
      } else if (data.status === 'error') {
        setError(data.message || 'An error occurred during scanning');
        setLoading(false);
      } else {
        // Continue polling
        setTimeout(() => pollScanResults(id), 1000);
      }
    } catch (error) {
      setError(error.response?.data?.error || 'An error occurred while checking scan status');
      setLoading(false);
    }
  };

  // Function to generate corrected code based on vulnerabilities and AI recommendations
  const generateCorrectedCode = (result) => {
    if (!result.static_analysis || !result.static_analysis.vulnerabilities || 
        result.static_analysis.vulnerabilities.length === 0) {
      return null;
    }

    const fileName = result.file.split('\\').pop().split('/').pop();
    let codeLines = result.original_code ? result.original_code.split('\n') : [];
    
    if (codeLines.length === 0) {
      return null;
    }

    // Deep copy of code lines to avoid modifying the original
    let correctedLines = [...codeLines];
    
    // Extract corrections from AI analysis
    let corrections = extractCorrectionsFromAI(result.ai_analysis, result.static_analysis.vulnerabilities);
    
    // Apply corrections
    for (const correction of corrections) {
      if (correction.lineNumber && correction.suggestedCode) {
        const lineIndex = correction.lineNumber - 1;
        if (lineIndex >= 0 && lineIndex < correctedLines.length) {
          correctedLines[lineIndex] = correction.suggestedCode;
        }
      }
    }
    
    return {
      fileName: fileName,
      code: correctedLines.join('\n'),
      hasCorrections: corrections.length > 0
    };
  };

  // Function to extract correction suggestions from AI analysis
  const extractCorrectionsFromAI = (aiAnalysis, vulnerabilities) => {
    if (!aiAnalysis) return [];
    
    const corrections = [];
    
    // Simple extraction of lines containing "Recommended fix:" or similar phrases
    const recommendationPattern = /line\s+(\d+)[\s\S]+?(recommended fix|suggested fix|fix)[\s\S]+?`([^`]+)`/gi;
    let match;
    
    while ((match = recommendationPattern.exec(aiAnalysis)) !== null) {
      corrections.push({
        lineNumber: parseInt(match[1]),
        suggestedCode: match[3].trim()
      });
    }
    
    // If no corrections found from AI analysis, create simple ones based on vulnerability types
    if (corrections.length === 0 && vulnerabilities.length > 0) {
      for (const vuln of vulnerabilities) {
        const lineNumbers = vuln.line_numbers || (vuln.line_number ? [vuln.line_number] : []);
        
        for (const lineNum of lineNumbers) {
          let suggestion = null;
          
          if (vuln.description.includes('eval')) {
            suggestion = '// SECURITY: Use a safer alternative to eval()';
          } else if (vuln.description.includes('command injection')) {
            suggestion = '// SECURITY: Use parameterized commands or input validation';
          } else if (vuln.description.includes('hardcoded')) {
            suggestion = '// SECURITY: Use environment variables or secure storage for credentials';
          } else if (vuln.description.includes('file')) {
            suggestion = '// SECURITY: Validate file paths and implement proper access controls';
          }
          
          if (suggestion) {
            corrections.push({
              lineNumber: lineNum,
              suggestedCode: suggestion
            });
          }
        }
      }
    }
    
    return corrections;
  };

  // Function to copy text to clipboard
  const copyToClipboard = (text, fileName) => {
    navigator.clipboard.writeText(text).then(
      () => {
        setSnackbarMessage(`${fileName} copied to clipboard`);
        setSnackbarOpen(true);
      },
      (err) => {
        console.error('Could not copy text: ', err);
        setSnackbarMessage('Failed to copy to clipboard');
        setSnackbarOpen(true);
      }
    );
  };

  const handleSnackbarClose = () => {
    setSnackbarOpen(false);
  };

  const renderResults = () => {
    if (!results) return null;

    return (
      <Paper elevation={3} sx={{ padding: 3, mt: 3 }}>
        <Typography variant="h6" gutterBottom>
          Results
        </Typography>
        
        {results.code_analysis && results.code_analysis.length > 0 ? (
          <>
            <Typography variant="subtitle1" gutterBottom>
              Code Analysis:
            </Typography>
            {results.code_analysis.map((result, index) => {
              // Extract filename from the full path
              const fileName = result.file.split('\\').pop().split('/').pop();
              
              // Check if there are vulnerabilities in static analysis
              const hasVulnerabilities = result.static_analysis && 
                                        result.static_analysis.vulnerabilities && 
                                        result.static_analysis.vulnerabilities.length > 0;
              
              // Generate corrected code if there are vulnerabilities
              if (hasVulnerabilities && !correctedCode[fileName]) {
                const generatedCode = generateCorrectedCode(result);
                if (generatedCode) {
                  setCorrectedCode(prev => ({
                    ...prev,
                    [fileName]: generatedCode
                  }));
                }
              }
              
              return (
                <Box key={index} sx={{ mb: 3, border: '1px solid #e0e0e0', borderRadius: 1, p: 2 }}>
                  <Typography variant="subtitle2" color="primary" gutterBottom>
                    File: {fileName}
                  </Typography>
                  
                  {result.code_changes && result.code_changes.length > 0 && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2" color="error" gutterBottom>
                        Required Code Changes:
                      </Typography>
                      {result.code_changes.map((change, changeIndex) => (
                        <Paper key={changeIndex} elevation={1} sx={{ p: 2, mb: 2, bgcolor: '#f5f5f5' }}>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            Line {change.line || 'Unknown'}
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 2 }}>
                            <Box sx={{ flex: 1 }}>
                              <Typography variant="caption" color="error">
                                Original Code:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#ffebee', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                                {change.original}
                              </Paper>
                            </Box>
                            <Box sx={{ flex: 1 }}>
                              <Typography variant="caption" color="success.main">
                                New Code:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#e8f5e9', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                                {change.new}
                              </Paper>
                            </Box>
                          </Box>
                        </Paper>
                      ))}
                    </Box>
                  )}

                  {result.static_analysis && result.static_analysis.vulnerabilities && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2" color="error" gutterBottom>
                        Vulnerabilities Found:
                      </Typography>
                      {result.static_analysis.vulnerabilities.map((vuln, vulnIndex) => (
                        <Paper key={vulnIndex} elevation={1} sx={{ p: 2, mb: 1, bgcolor: '#fff3e0' }}>
                          <Typography variant="body2" color="error">
                            {vuln.severity}: {vuln.description}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            Line {vuln.line_number}: {vuln.line_content}
                          </Typography>
                          
                          {/* Show secure code example based on vulnerability type */}
                          {vuln.description.includes('Command Injection') && (
                            <Box sx={{ mt: 1, p: 1, bgcolor: '#f5f5f5', borderRadius: 1 }}>
                              <Typography variant="caption" color="success.main">
                                Secure Code Example:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#e8f5e9', fontFamily: 'monospace' }}>
                                subprocess.run(command, shell=False, check=True)
                              </Paper>
                            </Box>
                          )}
                          
                          {vuln.description.includes('SQL Injection') && (
                            <Box sx={{ mt: 1, p: 1, bgcolor: '#f5f5f5', borderRadius: 1 }}>
                              <Typography variant="caption" color="success.main">
                                Secure Code Example:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#e8f5e9', fontFamily: 'monospace' }}>
                                cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                              </Paper>
                            </Box>
                          )}
                          
                          {vuln.description.includes('Path Traversal') && (
                            <Box sx={{ mt: 1, p: 1, bgcolor: '#f5f5f5', borderRadius: 1 }}>
                              <Typography variant="caption" color="success.main">
                                Secure Code Example:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#e8f5e9', fontFamily: 'monospace' }}>
                                safe_path = os.path.normpath(os.path.join("data", filename)){'\n'}
                                if not safe_path.startswith("data/"):{'\n'}
                                {'    '}raise ValueError("Invalid file path"){'\n'}
                                with open(safe_path, "r") as f:
                              </Paper>
                            </Box>
                          )}
                          
                          {vuln.description.includes('Hardcoded Credentials') && (
                            <Box sx={{ mt: 1, p: 1, bgcolor: '#f5f5f5', borderRadius: 1 }}>
                              <Typography variant="caption" color="success.main">
                                Secure Code Example:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#e8f5e9', fontFamily: 'monospace' }}>
                                password = os.getenv("DB_PASSWORD")
                              </Paper>
                            </Box>
                          )}
                          
                          {vuln.description.includes('Insecure Random') && (
                            <Box sx={{ mt: 1, p: 1, bgcolor: '#f5f5f5', borderRadius: 1 }}>
                              <Typography variant="caption" color="success.main">
                                Secure Code Example:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#e8f5e9', fontFamily: 'monospace' }}>
                                return secrets.token_hex(4)
                              </Paper>
                            </Box>
                          )}
                          
                          {vuln.description.includes('Insecure Cryptography') && (
                            <Box sx={{ mt: 1, p: 1, bgcolor: '#f5f5f5', borderRadius: 1 }}>
                              <Typography variant="caption" color="success.main">
                                Secure Code Example:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#e8f5e9', fontFamily: 'monospace' }}>
                                return hashlib.sha256(password.encode()).hexdigest()
                              </Paper>
                            </Box>
                          )}
                          
                          {vuln.description.includes('Insecure Deserialization') && (
                            <Box sx={{ mt: 1, p: 1, bgcolor: '#f5f5f5', borderRadius: 1 }}>
                              <Typography variant="caption" color="success.main">
                                Secure Code Example:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#e8f5e9', fontFamily: 'monospace' }}>
                                return json.loads(data)
                              </Paper>
                            </Box>
                          )}
                          
                          {vuln.description.includes('SSRF') && (
                            <Box sx={{ mt: 1, p: 1, bgcolor: '#f5f5f5', borderRadius: 1 }}>
                              <Typography variant="caption" color="success.main">
                                Secure Code Example:
                              </Typography>
                              <Paper elevation={0} sx={{ p: 1, bgcolor: '#e8f5e9', fontFamily: 'monospace' }}>
                                def validate_url(url):{'\n'}
                                {'    '}parsed = urllib.parse.urlparse(url){'\n'}
                                {'    '}if parsed.netloc not in ALLOWED_DOMAINS:{'\n'}
                                {'        '}raise ValueError("Domain not allowed"){'\n'}
                                {'    '}return url{'\n'}
                                return requests.get(validate_url(url), timeout=5)
                              </Paper>
                            </Box>
                          )}
                        </Paper>
                      ))}
                    </Box>
                  )}

                  {result.ai_analysis && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        AI Analysis:
                      </Typography>
                      <Paper elevation={1} sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                        <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                          {result.ai_analysis}
                        </Typography>
                      </Paper>
                    </Box>
                  )}
                </Box>
              );
            })}
          </>
        ) : (
          <Typography variant="body1">No code analysis results available.</Typography>
        )}

        {tab === 0 && results.dependency_vulnerabilities && 
         results.dependency_vulnerabilities.length > 0 && (
          <>
            <Typography variant="subtitle1" gutterBottom sx={{ mt: 3 }}>
              Dependency Vulnerabilities:
            </Typography>
            {results.dependency_vulnerabilities.map((vuln, index) => (
              <Box key={index} sx={{ mb: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  Package: {vuln.package} (v{vuln.version})
                </Typography>
                {vuln.vulnerabilities?.map((v, i) => (
                  <Box key={i} sx={{ ml: 2 }}>
                    <Typography variant="body2">
                      CVE: {v.cve_id} (Severity: {v.severity})
                    </Typography>
                    <Typography variant="body2">
                      {v.description}
                    </Typography>
                  </Box>
                ))}
              </Box>
            ))}
          </>
        )}
        
        {results.summary && (
          <Box sx={{ mt: 3, p: 2, bgcolor: '#f5f5f5', borderRadius: 1 }}>
            <Typography variant="subtitle1" gutterBottom>
              Summary:
            </Typography>
            <Typography variant="body2">
              Total Files Analyzed: {results.summary.total_files_analyzed}
            </Typography>
            <Typography variant="body2">
              Total Vulnerabilities: {results.summary.total_vulnerabilities}
            </Typography>
            <Typography variant="body2" color="error">
              Critical Vulnerabilities: {results.summary.critical_vulnerabilities}
            </Typography>
            <Typography variant="body2" color="warning.main">
              High Severity Issues: {results.summary.high_vulnerabilities}
            </Typography>
            <Typography variant="body2" color="info.main">
              Medium Severity Issues: {results.summary.medium_vulnerabilities}
            </Typography>
            <Typography variant="body2" color="success.main">
              Low Severity Issues: {results.summary.low_vulnerabilities}
            </Typography>
          </Box>
        )}
      </Paper>
    );
  };

  const renderProgress = () => {
    if (!loading) return null;

    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          {scanStatus}
        </Typography>
        <LinearProgress variant="determinate" value={scanProgress} />
        <Typography variant="body2" color="text.secondary" align="right" sx={{ mt: 1 }}>
          {scanProgress}%
        </Typography>
      </Box>
    );
  };

  return (
    <Container maxWidth="md">
      <Paper elevation={3} sx={{ padding: 3, mt: 4 }}>
        <Typography variant="h5" gutterBottom>
          Code Security Scanner
        </Typography>

        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
          <Tabs value={tab} onChange={handleTabChange}>
            <Tab label="GitHub Repository" />
            <Tab label="Code Input" />
          </Tabs>
        </Box>

        {tab === 0 ? (
          <TextField
            fullWidth
            label="GitHub Repository URL"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            margin="normal"
            placeholder="https://github.com/username/repository"
          />
        ) : (
          <TextField
            fullWidth
            label="Code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            margin="normal"
            multiline
            rows={10}
            placeholder="Paste your code here..."
          />
        )}

        <FormControl fullWidth margin="normal">
          <InputLabel>Language</InputLabel>
          <Select
            value={language}
            onChange={handleLanguageChange}
            label="Language"
          >
            <MenuItem value="python">Python</MenuItem>
            <MenuItem value="javascript">JavaScript</MenuItem>
          </Select>
        </FormControl>

        <FormControlLabel
          control={
            <Checkbox
              checked={checkDependencies}
              onChange={(e) => setCheckDependencies(e.target.checked)}
            />
          }
          label="Check Dependencies"
        />

        <Button
          variant="contained"
          color="primary"
          onClick={handleScan}
          disabled={loading || (tab === 0 ? !repoUrl : !code)}
          sx={{ mt: 2 }}
        >
          {loading ? <CircularProgress size={24} /> : 'Scan'}
        </Button>

        {error && (
          <Typography color="error" sx={{ mt: 2 }}>
            {error}
          </Typography>
        )}
      </Paper>

      {renderProgress()}

      {renderResults()}

      <Snackbar
        open={snackbarOpen}
        autoHideDuration={3000}
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert onClose={handleSnackbarClose} severity="success" variant="filled">
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default Scanner;
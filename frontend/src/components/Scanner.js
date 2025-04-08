import React, { useState } from 'react';
import { TextField, Button, Typography, Box, Paper, List, ListItem, ListItemText, Divider, Chip } from '@mui/material';
import { styled } from '@mui/material/styles';

const StyledPaper = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(3),
  marginBottom: theme.spacing(3),
}));

const StyledListItem = styled(ListItem)(({ theme }) => ({
  marginBottom: theme.spacing(2),
}));

const Scanner = () => {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('python');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [correctedCode, setCorrectedCode] = useState('');

  const handleScan = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code, language }),
      });
      const data = await response.json();
      setResults(data);
      
      // Generate corrected code
      if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        let corrected = code;
        data.vulnerabilities.forEach(vuln => {
          if (vuln.suggested_fix) {
            const lines = corrected.split('\n');
            const lineIndex = vuln.line_number - 1;
            if (lineIndex >= 0 && lineIndex < lines.length) {
              lines[lineIndex] = vuln.suggested_fix.split(':')[1].trim();
            }
            corrected = lines.join('\n');
          }
        });
        setCorrectedCode(corrected);
      } else {
        setCorrectedCode(code);
      }
    } catch (error) {
      console.error('Error scanning code:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <StyledPaper>
        <Typography variant="h5" gutterBottom>
          Code Scanner
        </Typography>
        <TextField
          fullWidth
          multiline
          rows={10}
          variant="outlined"
          label="Enter your code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          margin="normal"
        />
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <TextField
            select
            label="Language"
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            SelectProps={{
              native: true,
            }}
            sx={{ minWidth: 120 }}
          >
            <option value="python">Python</option>
            <option value="javascript">JavaScript</option>
          </TextField>
          <Button
            variant="contained"
            color="primary"
            onClick={handleScan}
            disabled={loading || !code}
          >
            {loading ? 'Scanning...' : 'Scan Code'}
          </Button>
        </Box>
      </StyledPaper>

      {results && (
        <>
          <StyledPaper>
            <Typography variant="h6" gutterBottom>
              Scan Results
            </Typography>
            <Typography variant="body1" gutterBottom>
              Total Vulnerabilities Found: {results.total_vulnerabilities}
            </Typography>
            <List>
              {results.vulnerabilities.map((vuln, index) => (
                <React.Fragment key={index}>
                  <StyledListItem>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="subtitle1">
                            {vuln.description}
                          </Typography>
                          <Chip
                            label={vuln.severity}
                            color={
                              vuln.severity === 'Critical'
                                ? 'error'
                                : vuln.severity === 'High'
                                ? 'warning'
                                : 'info'
                            }
                            size="small"
                          />
                        </Box>
                      }
                      secondary={
                        <>
                          <Typography variant="body2" color="text.secondary">
                            Line {vuln.line_number}: {vuln.line_content}
                          </Typography>
                          <Typography variant="body2" color="primary">
                            Suggested Fix: {vuln.suggested_fix}
                          </Typography>
                        </>
                      }
                    />
                  </StyledListItem>
                  {index < results.vulnerabilities.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          </StyledPaper>

          <StyledPaper>
            <Typography variant="h6" gutterBottom>
              Corrected Code
            </Typography>
            <TextField
              fullWidth
              multiline
              rows={10}
              variant="outlined"
              value={correctedCode}
              InputProps={{
                readOnly: true,
              }}
            />
            <Box sx={{ mt: 2 }}>
              <Button
                variant="contained"
                color="primary"
                onClick={() => {
                  navigator.clipboard.writeText(correctedCode);
                }}
              >
                Copy Corrected Code
              </Button>
            </Box>
          </StyledPaper>
        </>
      )}
    </Box>
  );
};

export default Scanner; 
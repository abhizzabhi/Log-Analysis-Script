# Log-Analysis-Script
This project is a Python-based log analysis tool designed to process web server logs, extract key metrics, and identify suspicious activities. The tool provides insights into server activity, such as the number of requests per IP address, the most frequently accessed endpoints, and potential security threats from excessive failed login attempts.

Installation
Clone the repository:
git clone https://github.com/your-username/log-analysis-tool.git                                                                  
cd log-analysis-tool                                                                                                              
Ensure Python 3.x is installed on your system.

Usage
Place your log file in the project directory or provide its path.                                                                 
Update the constants in the script (optional):                                                                                    
LOG_FILE: Path to your log file.                                                                                                  
OUTPUT_CSV: Name of the output CSV file.                                                                                          
FAILED_LOGIN_THRESHOLD: Set a threshold for detecting suspicious IPs.                                                                                                                                                                                               
Run the script:                                                                                                                   
python log_analysis.py                                                                                                            
View the results:                                                                                                                 
Terminal: Summary of key metrics.                                                                                                 
CSV File: Check log_analysis_results.csv for detailed insights.

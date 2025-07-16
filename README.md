# 🛡️ AI Threat Intelligence Pipeline

An intelligent, automated threat intelligence system that monitors cybersecurity RSS feeds, processes threat data using AI, and delivers actionable security alerts via email.

## 🎯 What This Project Does

This pipeline automatically:
1. **Fetches** RSS feeds from major cybersecurity sources (TheHackersNews, BleepingComputer)
2. **Processes** articles using OpenAI to categorize threats (CVE vs News)
3. **Researches** CVE vulnerabilities using Perplexity AI for accurate, up-to-date information
4. **Formats** professional HTML email reports with proper categorization and deduplication
5. **Sends** automated security alerts via Gmail API

### 🔍 Key Features

- **AI-Powered Classification**: Uses OpenAI GPT-4o-mini to categorize security content
- **CVE Research**: Leverages Perplexity AI for real-time vulnerability research
- **Smart Deduplication**: Removes duplicate CVE entries, keeping the most complete data
- **Unified CVE Data Structure**: New structured approach with individual CVE dictionaries
- **Individual CVE Research**: Each CVE ID is researched separately for accurate scoring
- **Highest Score Classification**: Critical/Non-Critical categorization based on highest CVSS score
- **Robust Error Handling**: Fallback mechanisms prevent data loss during processing
- **Batch Processing**: Handles large datasets without context window limitations
- **Professional Email Templates**: Clean, scannable HTML emails for security teams
- **Modular Prompt System**: All AI prompts are externalized for easy customization
- **Automated Scheduling**: Can be run via cron jobs for continuous monitoring
- **Comprehensive Logging**: Detailed execution metrics and error tracking

## 📋 Prerequisites

- Python 3.8+
- OpenAI API access
- Perplexity AI API access
- Google Cloud Project with Gmail API enabled
- Gmail account for sending emails

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/arielkl-wix/AI-Threat-Hunting.git
cd AI-Threat-Hunting
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Set Up Environment Variables
Create a `.env` file in the root directory:
```bash
# .env file
OPENAI_API_KEY=your_openai_api_key_here
PERPLEXITY_API_KEY=your_perplexity_api_key_here
RECIPIENT_EMAIL=your_email@domain.com
```

### 4. Configure Gmail API Access
Create `credentials.json` (Google OAuth2 credentials):
```json
{
  "installed": {
    "client_id": "your_client_id.apps.googleusercontent.com",
    "project_id": "your_project_id",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "your_client_secret",
    "redirect_uris": ["http://localhost"]
  }
}
```

### 5. Run the Pipeline
```bash
python AI_Threat_Intel.py
```

On first run, you'll be prompted to authorize Gmail access. This creates `token.json` automatically.

## 🔧 Detailed Setup Guide

### API Key Setup

#### OpenAI API Key
1. Visit [OpenAI Platform](https://platform.openai.com/)
2. Create an account or sign in
3. Go to API Keys section
4. Create a new API key
5. Add to your `.env` file as `OPENAI_API_KEY`

#### Perplexity AI API Key
1. Visit [Perplexity AI](https://www.perplexity.ai/)
2. Sign up for API access
3. Generate an API key
4. Add to your `.env` file as `PERPLEXITY_API_KEY`

### Gmail API Setup

#### 1. Create Google Cloud Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the Gmail API:
   - Go to "APIs & Services" → "Library"
   - Search for "Gmail API"
   - Click "Enable"

#### 2. Create OAuth2 Credentials
1. Go to "APIs & Services" → "Credentials"
2. Click "Create Credentials" → "OAuth 2.0 Client IDs"
3. Choose "Desktop Application"
4. Download the JSON file
5. Rename it to `credentials.json` and place in project root

#### 3. Configure OAuth Consent Screen
1. Go to "APIs & Services" → "OAuth consent screen"
2. Choose "External" for user type
3. Fill required fields:
   - App name: "AI Threat Hunting"
   - User support email: your email
   - Developer contact: your email
4. Add scopes: `https://www.googleapis.com/auth/gmail.send`
5. Add your email as a test user

### Configuration Files

#### `config.json`
```json
{
  "openai_model": "gpt-4o-mini",
  "openai_temperature": 0.1,
  "perplexity_model": "sonar-pro",
  "credentials_file": "credentials.json",
  "email_subject": "🚨 Threat Intelligence Weekly Report",
  "feed_urls": [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/"
  ],
  "news_days_filter": 7,
  "web_timeout": 30,
  "web_connect_timeout": 10,
  "max_retries": 3
}
```

#### `.env` (Environment Variables)
```bash
# Required API Keys
OPENAI_API_KEY=sk-your-openai-key-here
PERPLEXITY_API_KEY=pplx-your-perplexity-key-here

# Email Configuration
RECIPIENT_EMAIL=security-team@yourcompany.com
```

#### `token.json` (Auto-generated)
This file is automatically created after first Gmail authorization. It contains:
- Access token
- Refresh token
- Client credentials
- Token expiration

**⚠️ Security Note**: All credential files (`.env`, `credentials.json`, `token.json`) are automatically ignored by Git via `.gitignore`.

## 📁 Project Structure

```
AI-Threat-Hunting/
├── AI_Threat_Intel.py              # Main pipeline script
├── config.json                     # Configuration settings
├── requirements.txt                # Python dependencies
├── .env                            # Environment variables (create this)
├── credentials.json                # Google OAuth2 credentials (create this)
├── token.json                      # Gmail API token (auto-generated)
├── cve_email_template.html         # CVE alert email template
├── news_email_template.html        # News digest email template
├── prompts/                        # AI prompts directory
│   ├── comprehensive_threat_processor.txt  # Main threat categorization
│   ├── perplexity_research.txt            # CVE research instructions
│   ├── cve_email_format.txt               # CVE email formatting
│   ├── news_email_format.txt              # News email formatting
│   ├── news_categorization.txt            # News categorization logic
│   ├── critical_cve_batch.txt             # Critical CVE batch processing
│   ├── non_critical_cve_batch.txt         # Non-critical CVE batch processing
│   └── news_batch.txt                     # News batch processing
└── README.md                       # This file
```

## 🔄 How It Works

### 1. Data Collection
- Fetches RSS feeds from cybersecurity sources
- Parses XML content and extracts article metadata
- Handles feed parsing errors gracefully

### 2. AI Processing
- **OpenAI Classification**: Categorizes articles as CVE or News using modular prompts
- **CVE Extraction**: Uses regex to find CVE identifiers
- **Batch Processing**: Splits large datasets to avoid context limits
- **News Categorization**: Groups news items into relevant security categories

### 3. Enhanced CVE Research
- **Individual CVE Research**: Each CVE ID is researched separately using Perplexity AI
- **Unified Data Structure**: CVEs stored as structured dictionaries with CVE_ID, CVE_Score, CVE_Link, CVE_Severity
- **Article-Level Context**: IOCs, action items, and affected systems extracted from article context
- **Data Validation**: Ensures accuracy from authoritative sources (NVD, MITRE)
- **Severity Assessment**: Classifies CVEs as Critical (highest CVSS ≥ 9.0) or Non-Critical

### 4. Robust Email Generation
- **Professional Templates**: Uses HTML templates for consistent formatting
- **Smart Deduplication**: Removes duplicate CVEs, keeping most complete data
- **Batch Processing**: Handles large volumes using specialized prompts
- **Fallback Mechanisms**: Creates backup HTML when AI processing fails
- **Error Recovery**: Multiple layers of error handling prevent data loss
- **Proper Formatting**: Converts markdown to HTML, cleans up AI output

### 5. Delivery & Monitoring
- **Gmail API**: Sends emails via authenticated Gmail account
- **Comprehensive Logging**: Detailed execution metrics and performance tracking
- **Error Handling**: Robust error handling and logging throughout
- **Verification Systems**: Multi-layer validation ensures no data loss

## 🆕 New CVE Data Structure

### Old Structure (Deprecated)
```python
item = {
    "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"],
    "cve_scores": ["9.8", "7.5"],
    "cve_links": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234", "..."],
    "severities": ["Critical", "High"]
}
```

### New Unified Structure
```python
item = {
    "cves": [
        {
            "CVE_ID": "CVE-2024-1234",
            "CVE_Score": "9.8",
            "CVE_Link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            "CVE_Severity": "Critical"
        },
        {
            "CVE_ID": "CVE-2024-5678",
            "CVE_Score": "7.5",
            "CVE_Link": "https://nvd.nist.gov/vuln/detail/CVE-2024-5678",
            "CVE_Severity": "High"
        }
    ]
}
```

### Benefits of New Structure
- **Individual CVE Research**: Each CVE is researched separately for accurate data
- **Structured Data**: Cleaner, more maintainable code
- **Backwards Compatibility**: Old structure still supported during transition
- **Enhanced Accuracy**: Better data validation and error handling
- **Improved Email Formatting**: Unified CVE display in email templates

## 📧 Email Output Examples

### CVE Alert Email
- **Critical CVEs**: High-severity vulnerabilities requiring immediate attention
- **Non-Critical CVEs**: Lower-severity issues for awareness
- **New Format**: `CVE-2024-1234 (hyperlink) - CVE Score: 9.8`
- **Unified Display**: All CVE information consolidated in single "CVE's Present" field
- **Details**: CVSS scores, affected systems, IOCs, action items

### News Digest Email
- **Categorized News**: Grouped by security topics (Data Breaches, Malware, etc.)
- **Context Analysis**: AI-generated insights and implications
- **Publication Dates**: Chronological organization within categories
- **Date Filtering**: Only includes news from the last 7 days (configurable)
- **Fallback HTML**: Backup formatting when AI processing fails

## 🔧 Enhanced Prompt System

### Core Processing Prompts
- **`comprehensive_threat_processor.txt`**: Main threat categorization with web search capabilities
- **`perplexity_research.txt`**: Individual CVE research with validation requirements

### Email Formatting Prompts
- **`cve_email_format.txt`**: CVE email formatting with unified CVE display
- **`news_email_format.txt`**: News email formatting with comprehensive validation

### Batch Processing Prompts
- **`critical_cve_batch.txt`**: Critical CVE batch formatting (CVSS ≥ 9.0)
- **`non_critical_cve_batch.txt`**: Non-critical CVE batch formatting (CVSS < 9.0)
- **`news_batch.txt`**: News item batch processing with fallback support

### Categorization Prompts
- **`news_categorization.txt`**: News categorization with validation checklists

### Prompt Features
- **Validation Checklists**: Built-in verification requirements
- **Error Prevention**: Instructions to prevent data loss
- **Structured Output**: Consistent JSON formatting
- **Fallback Instructions**: Guidance for handling failures

## 🚨 Enhanced Error Handling

### CVE Processing
- **Individual Research**: Each CVE researched separately to prevent batch failures
- **Fallback Categorization**: Score-based classification when research fails
- **Data Validation**: Multiple verification steps for CVE data integrity

### News Processing
- **Categorization Validation**: Ensures all items are properly categorized
- **Batch Processing Recovery**: Fallback HTML generation for failed batches
- **Item Tracking**: Comprehensive logging tracks items through entire process
- **Final Verification**: Multi-layer validation prevents data loss

### Email Generation
- **Template Fallbacks**: Backup email generation when AI processing fails
- **Content Validation**: Ensures all items are included in final emails
- **HTML Cleaning**: Robust content sanitization and formatting

## 🔧 Customization

### Adding New RSS Feeds
Edit `config.json`:
```json
{
  "feed_urls": [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://your-new-feed.com/rss"
  ]
}
```

### Modifying Email Templates
- Edit `cve_email_template.html` for CVE alerts
- Edit `news_email_template.html` for news digests
- Use placeholders like `{{CRITICAL_CVE_ITEMS}}` for dynamic content

### Customizing AI Prompts
All AI prompts are stored in the `prompts/` directory for easy modification:

**Core Processing:**
- `comprehensive_threat_processor.txt`: Main threat categorization with web search
- `perplexity_research.txt`: Individual CVE research with validation

**Email Formatting:**
- `cve_email_format.txt`: CVE email formatting with unified structure
- `news_email_format.txt`: News email formatting with validation

**Batch Processing:**
- `critical_cve_batch.txt`: Critical CVE batch formatting
- `non_critical_cve_batch.txt`: Non-critical CVE batch formatting
- `news_batch.txt`: News item batch processing with fallback support

**Categorization:**
- `news_categorization.txt`: News categorization with validation checklists

Simply edit these files to customize how the AI processes and formats content. Changes take effect immediately without modifying the main code.

### Configuration Options
Edit `config.json` to customize:
- `news_days_filter`: How many days back to include news (default: 7)
- `openai_temperature`: AI creativity level (0.1 = more focused)
- `web_timeout`: Request timeout for feed fetching
- `email_subject`: Subject line for security emails

## 🚨 Troubleshooting

### Common Issues

#### Gmail API Authorization
```bash
# Error: Gmail API not enabled
# Solution: Enable Gmail API in Google Cloud Console
```

#### OpenAI Rate Limits
```bash
# Error: Rate limit exceeded
# Solution: The pipeline uses gpt-4o-mini (10,000 RPM) to avoid limits
```

#### Missing Environment Variables
```bash
# Error: API key not found
# Solution: Ensure .env file exists with all required keys
```

#### CVE Data Issues
```bash
# Error: CVE information missing
# Solution: Check Perplexity API access and CVE research prompts
```

### Logging
The pipeline provides detailed logging:
- Processing statistics
- Error messages with fallback actions
- Email delivery status
- Performance metrics
- Item tracking through entire process

## 📊 Performance Metrics

Typical execution times:
- **Feed Processing**: 10-30 seconds
- **AI Classification**: 2-5 minutes
- **Individual CVE Research**: 5-10 minutes (improved accuracy)
- **Email Generation**: 1-3 minutes
- **Total Runtime**: 8-20 minutes

### Performance Improvements
- **Parallel Processing**: ThreadPoolExecutor for concurrent operations
- **Batch Processing**: Optimized for large datasets
- **Error Recovery**: Fallback mechanisms prevent re-processing
- **Efficient Logging**: Detailed metrics without performance impact

## 🔒 Security Considerations

- **API Keys**: Stored in `.env` file (not committed to Git)
- **OAuth Tokens**: Automatically refreshed by Google client library
- **Rate Limiting**: Built-in delays to respect API limits
- **Error Handling**: Graceful failure without exposing sensitive data
- **Data Validation**: Multiple verification layers prevent data corruption

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly with the new prompt system
5. Submit a pull request

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section
2. Review the logs for error messages
3. Verify prompt configurations in `/prompts/` directory
4. Check CVE data structure compatibility
5. Open an issue on GitHub
6. Include relevant log output and configuration (without sensitive data)

## 🔄 Automation

### Cron Job Setup
Run the pipeline automatically:
```bash
# Edit crontab
crontab -e

# Add line for daily execution at 9 AM
0 9 * * * /usr/bin/python3 /path/to/AI-Threat-Hunting/AI_Threat_Intel.py
```

### Systemd Service
Create a systemd service for more advanced scheduling and monitoring.

## 🎯 Recent Major Updates

### CVE Data Structure Overhaul
- **Unified CVE Structure**: Replaced separate arrays with structured dictionaries
- **Individual Research**: Each CVE ID researched separately for accuracy
- **Backwards Compatibility**: Supports old structure during transition
- **Enhanced Validation**: Multiple verification layers

### Robust Error Handling
- **Fallback Mechanisms**: Prevents data loss during processing failures
- **Comprehensive Logging**: Detailed tracking of items through entire pipeline
- **Recovery Systems**: Automatic fallback HTML generation
- **Validation Checklists**: Built into all prompts

### Enhanced Email Formatting
- **Unified CVE Display**: Single "CVE's Present" field with hyperlinks
- **Improved Templates**: Better organization and readability
- **Batch Processing**: Optimized for large datasets
- **Professional Styling**: Clean, scannable HTML format

### Prompt System Improvements
- **Validation Requirements**: Built-in verification for all prompts
- **Error Prevention**: Instructions to prevent common failures
- **Structured Output**: Consistent JSON formatting across all prompts
- **Fallback Instructions**: Guidance for handling edge cases

---

**🎯 Ready to start hunting threats with AI? Follow the setup guide above and you'll be receiving automated security intelligence with enhanced accuracy and reliability!** 

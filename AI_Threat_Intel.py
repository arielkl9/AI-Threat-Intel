#!/usr/bin/env python3
import json
import logging
import re
import base64
import requests
from typing import List, Optional, Dict
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from openai import OpenAI
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import feedparser
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from dotenv import load_dotenv
import html

def load_config(config_path: str = "config.json") -> dict:
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    config['openai_api_key'] = os.getenv('OPENAI_API_KEY', config.get('openai_api_key'))
    config['perplexity_api_key'] = os.getenv('PERPLEXITY_API_KEY', config.get('perplexity_api_key'))
    config['recipient_email'] = os.getenv('RECIPIENT_EMAIL', config.get('recipient_email'))

    return config

class ThreatIntelItem(dict):
    def __init__(self, title: str, description: str, link: str, pub_date: str, category: Optional[str] = None,
                 cves: Optional[List[Dict]] = None, affected_systems: Optional[List[str]] = None, 
                 ioc: Optional[List[str]] = None, action_items: Optional[List[str]] = None, 
                 source_url: Optional[str] = None, versions_affected: Optional[List[str]] = None, 
                 news_link: Optional[str] = None, research_sources: Optional[List[str]] = None,
                 latest_updates: Optional[str] = None,
                 cve_ids: Optional[List[str]] = None, cve_scores: Optional[List[str]] = None, 
                 cve_links: Optional[List[str]] = None, severities: Optional[List[str]] = None,
                 cve_score: Optional[str] = None, cve_link: Optional[str] = None, 
                 severity: Optional[str] = None):
        
        if cves is None and cve_ids:
            cves = []
            for i, cve_id in enumerate(cve_ids):
                cve_dict = {"CVE_ID": cve_id}
                
                if cve_scores and i < len(cve_scores):
                    cve_dict["CVE_Score"] = cve_scores[i]
                elif cve_score and i == 0:
                    cve_dict["CVE_Score"] = cve_score
                
                if cve_links and i < len(cve_links):
                    cve_dict["CVE_Link"] = cve_links[i]
                elif cve_link and i == 0:
                    cve_dict["CVE_Link"] = cve_link
                
                if severities and i < len(severities):
                    cve_dict["CVE_Severity"] = severities[i]
                elif severity and i == 0:
                    cve_dict["CVE_Severity"] = severity
                
                cves.append(cve_dict)
            
        super().__init__(title=title, description=description, link=link, pub_date=pub_date, category=category,
                         cves=cves or [], affected_systems=affected_systems, ioc=ioc, action_items=action_items, 
                         source_url=source_url, versions_affected=versions_affected, news_link=news_link,
                         research_sources=research_sources, latest_updates=latest_updates)

    def __setattr__(self, key, value):
        self[key] = value

    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError:
            if item == 'cve_ids':
                cves = self.get('cves', [])
                return [cve.get('CVE_ID') for cve in cves if cve.get('CVE_ID')]
            elif item == 'cve_scores':
                cves = self.get('cves', [])
                return [cve.get('CVE_Score') for cve in cves if cve.get('CVE_Score')]
            elif item == 'cve_links':
                cves = self.get('cves', [])
                return [cve.get('CVE_Link') for cve in cves if cve.get('CVE_Link')]
            elif item == 'severities':
                cves = self.get('cves', [])
                return [cve.get('CVE_Severity') for cve in cves if cve.get('CVE_Severity')]
            elif item == 'cve_score':
                cves = self.get('cves', [])
                return cves[0].get('CVE_Score') if cves else None
            elif item == 'cve_link':
                cves = self.get('cves', [])
                return cves[0].get('CVE_Link') if cves else None
            elif item == 'severity':
                cves = self.get('cves', [])
                return cves[0].get('CVE_Severity') if cves else None
            else:
                raise AttributeError(f"'ThreatIntelItem' object has no attribute '{item}'")

class EmailSender:
    def __init__(self, config: dict):
        self.credentials_file = config['credentials_file']
        self.recipient_email = config['recipient_email']
        self.scopes = ["https://www.googleapis.com/auth/gmail.send"]
        self.service = None
    def _get_creds(self):
        token_file = Path("token.json")
        if token_file.exists():
            return Credentials.from_authorized_user_file(token_file, self.scopes)
        flow = InstalledAppFlow.from_client_secrets_file(self.credentials_file, self.scopes)
        creds = flow.run_local_server(port=0)
        token_file.write_text(creds.to_json())
        return creds
    def _build_service(self):
        if not self.service:
            self.service = build("gmail", "v1", credentials=self._get_creds())
        return self.service
    def send_email(self, subject: str, html_content: str) -> bool:
        try:
            service = self._build_service()
            msg = MIMEMultipart()
            msg["From"] = "me"
            msg["To"] = self.recipient_email
            msg["Subject"] = subject
            msg.attach(MIMEText(html_content, 'html'))
            email_message = {"raw": base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")}
            response = service.users().messages().send(userId="me", body=email_message).execute()
            logger.info(f"Email sent successfully: {response['id']}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

class ThreatIntelPipeline:
    def __init__(self, config: dict):
        self.config = config
        self.openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.email_sender = EmailSender(config)
        
        perplexity_api_key = os.getenv('PERPLEXITY_API_KEY')
        if perplexity_api_key:
            self.perplexity_client = OpenAI(
                api_key=perplexity_api_key,
                base_url="https://api.perplexity.ai"
            )
        else:
            self.perplexity_client = None
            logger.warning("Perplexity API key not found in environment variables")
    
    def clean_html_content(self, content: str) -> str:
        if not content:
            return content
        
        content = re.sub(r'```html\s*', '', content, flags=re.IGNORECASE)
        content = re.sub(r'```\s*', '', content, flags=re.IGNORECASE)
        
        content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', content)
        
        content = re.sub(r'\*(.*?)\*', r'<em>\1</em>', content)
        
        content = html.unescape(content)
        
        content = re.sub(r'\n\s*\n', '\n\n', content)
        content = re.sub(r'[ \t]+', ' ', content)
        
        content = re.sub(r'- \*\*(.*?)\*\*:', r'- <strong>\1:</strong>', content)
        
        lines = content.split('\n')
        cleaned_lines = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('<') and not line.endswith('>'):
                cleaned_lines.append(line)
            elif line:
                cleaned_lines.append(line)
        
        content = '\n'.join(cleaned_lines)
        
        return content
    
    def filter_news_by_date(self, news_items: List[Dict], days_back: int = 7) -> List[Dict]:
        if not news_items:
            return []
        
        from datetime import datetime, timedelta
        import dateutil.parser
        
        cutoff_date = datetime.now() - timedelta(days=days_back)
        logger.info(f"Filtering news items published after {cutoff_date.strftime('%Y-%m-%d %H:%M:%S')} ({days_back} days ago)")
        
        filtered_items = []
        
        for item in news_items:
            try:
                pub_date_str = item.get('pub_date', '')
                if not pub_date_str:
                    logger.warning(f"No publication date for item: {item.get('title', 'Unknown')[:50]}...")
                    continue
                
                try:
                    pub_date = dateutil.parser.parse(pub_date_str)
                    if pub_date.tzinfo is not None:
                        pub_date = pub_date.replace(tzinfo=None)
                except Exception as e:
                    logger.warning(f"Could not parse date '{pub_date_str}' for item: {item.get('title', 'Unknown')[:50]}... Error: {e}")
                    continue
                
                if pub_date >= cutoff_date:
                    item['parsed_date'] = pub_date
                    filtered_items.append(item)
                else:
                    logger.debug(f"Filtered out old item ({pub_date.strftime('%Y-%m-%d')}): {item.get('title', 'Unknown')[:50]}...")
                    
            except Exception as e:
                logger.warning(f"Error processing date for item: {item.get('title', 'Unknown')[:50]}... Error: {e}")
                continue
        
        filtered_items.sort(key=lambda x: x.get('parsed_date', datetime.min), reverse=True)
        
        logger.info(f"Filtered news items: {len(news_items)} → {len(filtered_items)} (within {days_back} days)")
        
        return filtered_items

    def categorize_news_items(self, news_items: List[Dict]) -> Dict[str, List[Dict]]:
        if not news_items:
            return {}
        
        logger.info(f"Categorizing {len(news_items)} news items into sub-categories")
        
        with open('prompts/news_categorization.txt', 'r', encoding='utf-8') as f:
            categorization_prompt_template = f.read()
        categorization_prompt = categorization_prompt_template.replace('{news_items}', json.dumps(news_items, indent=2, default=str))
        categorization_prompt = categorization_prompt.replace('{item_count}', str(len(news_items)))

        try:
            response = self.openai_client.chat.completions.create(
                model=self.config.get('openai_model', 'gpt-4'),
                messages=[{"role": "user", "content": categorization_prompt}],
                temperature=0.1,
            )
            
            categorization_result = response.choices[0].message.content
            if categorization_result:
                try:
                    if '```json' in categorization_result:
                        categorization_result = categorization_result.split('```json')[1].split('```')[0].strip()
                    elif '```' in categorization_result:
                        categorization_result = categorization_result.split('```')[1].split('```')[0].strip()
                    
                    categories = json.loads(categorization_result)
                    
                    all_indices = set()
                    for indices in categories.values():
                        all_indices.update(indices)
                    
                    expected_indices = set(range(len(news_items)))
                    missing_indices = expected_indices - all_indices
                    
                    if missing_indices:
                        logger.warning(f"Categorization missing {len(missing_indices)} items: {missing_indices}")
                        if "Security News" not in categories:
                            categories["Security News"] = []
                        categories["Security News"].extend(list(missing_indices))
                    
                    duplicate_indices = []
                    seen_indices = set()
                    for indices in categories.values():
                        for idx in indices:
                            if idx in seen_indices:
                                duplicate_indices.append(idx)
                            seen_indices.add(idx)
                    
                    if duplicate_indices:
                        logger.warning(f"Found duplicate indices in categorization: {duplicate_indices}")
                    
                    categorized_items = {}
                    for category_name, indices in categories.items():
                        categorized_items[category_name] = []
                        for idx in indices:
                            if 0 <= idx < len(news_items):
                                categorized_items[category_name].append(news_items[idx])
                    
                    total_categorized = sum(len(items) for items in categorized_items.values())
                    if total_categorized != len(news_items):
                        logger.error(f"Categorization validation failed: {len(news_items)} items → {total_categorized} categorized")
                    
                    for category, items in categorized_items.items():
                        logger.info(f"Category '{category}': {len(items)} items")
                    
                    return categorized_items
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse categorization JSON: {e}")
                    logger.error(f"Response was: {categorization_result}")
                    
        except Exception as e:
            logger.error(f"Error categorizing news items: {e}")
        
        logger.warning("Using fallback categorization - single category")
        return {"Security News": news_items}

    def validate_html_structure(self, html_content: str) -> str:
        if not html_content:
            return html_content
        
        open_divs = html_content.count('<div')
        close_divs = html_content.count('</div>')
        
        if open_divs > close_divs:
            html_content += '</div>' * (open_divs - close_divs)
        
        html_content = re.sub(r'<([^>]+)>', lambda m: '<' + m.group(1).strip() + '>', html_content)
        
        return html_content
    
    def deduplicate_cve_items(self, cve_items: List[Dict]) -> List[Dict]:
        if not cve_items:
            return cve_items
        
        logger.info(f"Deduplicating {len(cve_items)} CVE items...")
        
        unique_cves = {}
        
        for item in cve_items:
            cve_ids = item.get('cve_ids', [])
            if cve_ids:
                cve_key = tuple(sorted(cve_ids))
            else:
                cve_key = item.get('title', '').lower().strip()
            
            if cve_key not in unique_cves:
                unique_cves[cve_key] = item
                logger.info(f"Added unique CVE: {cve_key}")
            else:
                existing_item = unique_cves[cve_key]
                current_item = item
                
                existing_fields = sum(1 for v in existing_item.values() if v is not None and v != [] and v != '')
                current_fields = sum(1 for v in current_item.values() if v is not None and v != [] and v != '')
                
                if current_fields > existing_fields:
                    unique_cves[cve_key] = current_item
                    logger.info(f"Replaced CVE {cve_key} with more complete data ({current_fields} vs {existing_fields} fields)")
                else:
                    logger.info(f"Kept existing CVE {cve_key} (duplicate removed)")
        
        deduplicated_items = list(unique_cves.values())
        logger.info(f"Deduplication complete: {len(cve_items)} → {len(deduplicated_items)} items")
        
        return deduplicated_items
        
    def fetch_feeds(self, urls):
        headers = {
            "User-Agent": 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
            'Accept': 'application/rss+xml,application/xml,text/xml,*/*;q=0.9',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        timeout = self.config.get('web_timeout', 30)
        feeds = []
        
        for url in urls:
            try:
                logger.info(f"Fetching feed: {url}")
                response = requests.get(url, headers=headers, timeout=timeout)
                if response.status_code == 200:
                    feed = feedparser.parse(response.content)
                    feeds.append({"url": url, "content": feed})
                    logger.info(f"Successfully fetched {url}")
                else:
                    logger.warning(f"Failed to fetch {url}: HTTP {response.status_code}")
            except Exception as e:
                logger.error(f"Error fetching {url}: {e}")
                
        return feeds
        
    def parse_xml_feeds(self, feeds):
        items = []
        
        for feed in feeds:
            try:
                logger.info(f"Parsing XML feed: {feed['url']}")
                for entry in feed['content'].entries:
                    try:
                        title = entry.get('title', '').strip()
                        
                        description = entry.get('description', '').strip()
                        
                        link = entry.get('link', '').strip()
                        
                        pub_date = entry.get('published', '').strip()
                        
                        if title:
                            item = ThreatIntelItem(
                                title=title,
                                description=description,
                                link=link,
                                pub_date=pub_date,
                                source_url=feed['url']
                            )
                            items.append(item)
                            logger.debug(f"Parsed item: {title[:50]}...")
                            
                    except Exception as e:
                        logger.warning(f"Error parsing individual item in {feed['url']}: {e}")
                        continue
                        
            except Exception as e:
                logger.error(f"Unexpected error parsing {feed['url']}: {e}")
                continue
        
        logger.info(f"XML parser extracted {len(items)} items from feeds")
        return items
        
    def parse_with_perplexity(self, items):
        if not self.perplexity_client:
            logger.warning("Perplexity API not configured, skipping enhancement")
            return items

        enhanced_items = []

        def enhance_item(item):
            try:
                if not self.perplexity_client:
                    logger.warning("Perplexity API not configured, skipping enhancement for this item")
                    return item

                with open('prompts/comprehensive_threat_processor.txt', 'r', encoding='utf-8') as f:
                    prompt_template = f.read()
                item_json = json.dumps(item, indent=2, default=str)
                prompt = prompt_template.replace('{item}', item_json)

                logger.info(f"Enhancing item with Perplexity analysis: {item['title']}")
                try:
                    response = self.perplexity_client.chat.completions.create(
                        model=self.config.get('perplexity_model', 'sonar-pro'),
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.1,
                    )

                    content = response.choices[0].message.content
                    if not content:
                        logger.error("Empty response from Perplexity enhancement phase for item")
                        return item

                    content = content.strip()
                    if '```json' in content:
                        start = content.find('```json') + 7
                        end = content.find('```', start)
                        if end != -1:
                            content = content[start:end].strip()
                    elif '```' in content:
                        start = content.find('```') + 3
                        end = content.find('```', start)
                        if end != -1:
                            content = content[start:end].strip()
                    if not content.startswith('{'):
                        m = re.search(r'\{.*\}', content, re.DOTALL)
                        if m:
                            content = m.group(0)

                    try:
                        parsed = json.loads(content)
                        if parsed:
                            item.update(parsed)
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON parsing error in Perplexity enhancement for item: {e}")
                except Exception as e:
                    logger.error(f"Perplexity enhancement error: {e}")
                return item
            except Exception as e:
                logger.error(f"Error in enhance_item function: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                return item

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(enhance_item, item) for item in items]
            
            logger.info(f"Waiting for all {len(futures)} OpenAI enhancement threads to complete...")
            for i, future in enumerate(as_completed(futures)):
                try:
                    result = future.result()
                    enhanced_items.append(result)
                    logger.info(f"Completed enhancement thread {i+1}/{len(futures)}")
                except Exception as e:
                    logger.error(f"Thread raised an exception: {e}")
                    import traceback
                    logger.error(f"Traceback: {traceback.format_exc()}")
            
            logger.info(f"All {len(futures)} OpenAI enhancement threads completed")

        logger.info(f"Enhanced {len(enhanced_items)} items with OpenAI analysis")
        return enhanced_items
        
    def research_cves(self, items):
        if not self.perplexity_client:
            logger.warning("Perplexity API not configured, skipping research")
            return items

        cve_items = [item for item in items if item.get('category') == 'CVE']
        logger.info(f"Researching {len(cve_items)} CVE items...")

        def research_cve(item):
            try:
                if not self.perplexity_client:
                    logger.warning("Perplexity API not configured, skipping research for this item")
                    return item
                
                cve_ids = item.get('cve_ids', [])
                if not cve_ids:
                    cves = item.get('cves', [])
                    cve_ids = [cve.get('CVE_ID') for cve in cves if cve.get('CVE_ID')]
                
                if cve_ids:
                    logger.info(f"Researching CVE: {item['title']} with CVE IDs: {cve_ids}")
                    with open('prompts/perplexity_research.txt', 'r', encoding='utf-8') as f:
                        prompt_template = f.read()
                    prompt = prompt_template.replace('{title}', item['title'])
                    prompt = prompt.replace('{description}', item['description'])
                    prompt = prompt.replace('{cve_ids}', ', '.join(cve_ids))
                    prompt = prompt.replace('{pub_date}', item['pub_date'])
                    try:
                        response = self.perplexity_client.chat.completions.create(
                            model=self.config.get('perplexity_model', 'sonar-pro'),
                            messages=[{"role": "user", "content": prompt}],
                            temperature=0.1,
                        )
                        content = response.choices[0].message.content
                        if not content:
                            logger.warning("Empty response from Perplexity research phase")
                            return item
                        content = content.strip()
                        if content.startswith('```json'):
                            content = content[7:]
                        if content.endswith('```'):
                            content = content[:-3]
                        content = content.strip()
                        try:
                            logger.debug(f"Parsing JSON content: {content[:200]}...")
                            result = json.loads(content)
                            logger.info(f"Perplexity research result for {item['title']}: {result}")
                            
                            if 'cves' in result and result['cves']:
                                item['cves'] = result['cves']
                                logger.info(f"Updated {len(result['cves'])} CVEs for {item['title']}")
                            
                            elif 'cve_scores' in result or 'cve_links' in result or 'severities' in result:
                                cves = []
                                for i, cve_id in enumerate(cve_ids):
                                    cve_dict = {"CVE_ID": cve_id}
                                    
                                    if result.get('cve_scores') and i < len(result['cve_scores']):
                                        cve_dict["CVE_Score"] = result['cve_scores'][i]
                                    if result.get('cve_links') and i < len(result['cve_links']):
                                        cve_dict["CVE_Link"] = result['cve_links'][i]
                                    if result.get('severities') and i < len(result['severities']):
                                        cve_dict["CVE_Severity"] = result['severities'][i]
                                    
                                    cves.append(cve_dict)
                                
                                item['cves'] = cves
                                logger.info(f"Converted old structure to new for {len(cves)} CVEs")
                            
                            article_fields = ['affected_systems', 'versions_affected', 'ioc', 'action_items', 
                                            'research_sources', 'latest_updates', 'category']
                            for field in article_fields:
                                if field in result:
                                    item[field] = result[field]
                            
                            if not item.get('news_link'):
                                item['news_link'] = item['link']
                                
                        except json.JSONDecodeError as e:
                            logger.error(f"Perplexity research JSON parsing error: {e}")
                            logger.error(f"Content that failed to parse: {content}")
                        except Exception as e:
                            logger.error(f"Error updating item with research results: {e}")
                    except Exception as e:
                        logger.error(f"Perplexity research API error: {e}")
                return item
            except Exception as e:
                logger.error(f"Error in research_cve function: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                return item

        researched_items = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(research_cve, item) for item in cve_items]
            
            logger.info(f"Waiting for all {len(futures)} Perplexity research threads to complete...")
            for i, future in enumerate(as_completed(futures)):
                try:
                    result = future.result()
                    researched_items.append(result)
                    logger.info(f"Completed research thread {i+1}/{len(futures)}")
                except Exception as e:
                    logger.error(f"Thread raised an exception: {e}")
                    import traceback
                    logger.error(f"Traceback: {traceback.format_exc()}")
            
            logger.info(f"All {len(futures)} Perplexity research threads completed")

        for researched_item in researched_items:
            for i, item in enumerate(items):
                if item['title'] == researched_item['title']:
                    items[i] = researched_item
                    break

        return items
        
    def categorize_cves_by_score(self, items):
        for item in items:
            cve_ids = item.get('cve_ids', [])
            cves = item.get('cves', [])
            
            if item.get('category') == 'CVE' and (cve_ids or cves):
                logger.info(f"Applying fallback categorization for CVE: {item['title']}")
                
                max_score = 0.0
                has_critical_severity = False
                
                if cves:
                    for cve in cves:
                        score = cve.get('CVE_Score')
                        if score:
                            try:
                                if isinstance(score, str):
                                    score_val = score.replace('CVSS ', '').strip()
                                    score_num = float(score_val)
                                else:
                                    score_num = float(score)
                                
                                max_score = max(max_score, score_num)
                                logger.debug(f"CVE {cve.get('CVE_ID')} score: {score_num}")
                            except (ValueError, TypeError):
                                logger.warning(f"Invalid score format for {cve.get('CVE_ID')}: {score}")
                                continue
                        
                        severity = cve.get('CVE_Severity')
                        if severity and str(severity).lower() == 'critical':
                            has_critical_severity = True
                else:
                    scores = item.get('cve_scores', [])
                    if not scores:
                        scores = [item.get('cve_score')] if item.get('cve_score') else []
                    
                    for score in scores:
                        if score:
                            try:
                                if isinstance(score, str):
                                    score_val = score.replace('CVSS ', '').strip()
                                    score_num = float(score_val)
                                else:
                                    score_num = float(score)
                                
                                max_score = max(max_score, score_num)
                            except (ValueError, TypeError):
                                logger.warning(f"Invalid score format: {score}")
                                continue
                    
                    severities = item.get('severities', [])
                    if not severities:
                        severities = [item.get('severity')] if item.get('severity') else []
                    
                    has_critical_severity = any(sev and str(sev).lower() == 'critical' for sev in severities)
                
                if max_score >= 9.0 or has_critical_severity:
                    item['category'] = 'Critical CVE'
                    logger.info(f"Categorized as Critical CVE (highest score: {max_score}, critical severity: {has_critical_severity}): {item['title']}")
                elif max_score > 0.0:
                    item['category'] = 'Non-Critical CVE'
                    logger.info(f"Categorized as Non-Critical CVE (highest score: {max_score}): {item['title']}")
                else:
                    item['category'] = 'Non-Critical CVE'
                    logger.info(f"Categorized as Non-Critical CVE (no valid score found): {item['title']}")
        
        return items
        
    def format_emails(self, items):
        cve_items = [item for item in items if item.get('category') and 'CVE' in item['category']]
        news_items = [item for item in items if item.get('category') == 'News']
        emails = {}
        
        logger.info(f"Total items for email formatting: {len(items)}")
        logger.info(f"CVE items found (before deduplication): {len(cve_items)}")
        logger.info(f"News items found: {len(news_items)}")
        
        cve_items = self.deduplicate_cve_items(cve_items)
        logger.info(f"CVE items after deduplication: {len(cve_items)}")
        
        categories = {}
        for item in items:
            cat = item.get('category', 'None')
            categories[cat] = categories.get(cat, 0) + 1
        logger.info(f"Category breakdown: {categories}")
        
        for i, item in enumerate(cve_items):
            logger.info(f"CVE Item {i+1}:")
            logger.info(f"  Title: {item.get('title', 'N/A')}")
            logger.info(f"  CVE IDs: {item.get('cve_ids', 'N/A')}")
            logger.info(f"  CVE Scores: {item.get('cve_scores', 'N/A')}")
            logger.info(f"  CVE Links: {item.get('cve_links', 'N/A')}")
            logger.info(f"  Severities: {item.get('severities', 'N/A')}")
            logger.info(f"  Affected Systems: {item.get('affected_systems', 'N/A')}")
            logger.info(f"  IOC: {item.get('ioc', 'N/A')}")
            logger.info(f"  Category: {item.get('category', 'N/A')}")
        
        if cve_items:
            logger.info(f"Formatting CVE email with {len(cve_items)} items")
            try:
                with open('cve_email_template.html', 'r', encoding='utf-8') as f:
                    template = f.read()
            except FileNotFoundError:
                logger.error("CVE email template not found")
                template = "<html><body><h1>CVE Alerts</h1>{CRITICAL_CVE_ITEMS}{NON_CRITICAL_CVE_ITEMS}</body></html>"
            
            critical_cves = [item for item in cve_items if item.get('category') == 'Critical CVE']
            non_critical_cves = [item for item in cve_items if item.get('category') == 'Non-Critical CVE']
            
            logger.info(f"Critical CVEs: {len(critical_cves)}")
            logger.info(f"Non-Critical CVEs: {len(non_critical_cves)}")
            
            batch_size = 5
            critical_sections = []
            non_critical_sections = []
            
            if critical_cves:
                for i in range(0, len(critical_cves), batch_size):
                    batch = critical_cves[i:i + batch_size]
                    batch_num = (i // batch_size) + 1
                    total_batches = (len(critical_cves) + batch_size - 1) // batch_size
                    
                    logger.info(f"Processing critical CVE batch {batch_num}/{total_batches} with {len(batch)} items")
                    
                    with open('prompts/critical_cve_batch.txt', 'r', encoding='utf-8') as f:
                        batch_prompt_template = f.read()
                    batch_prompt = batch_prompt_template.replace('{batch_count}', str(len(batch)))
                    batch_prompt = batch_prompt.replace('{batch_data}', json.dumps(batch, indent=2, default=str))
                    
                    try:
                        response = self.openai_client.chat.completions.create(
                            model=self.config.get('openai_model', 'gpt-4'),
                            messages=[{"role": "user", "content": batch_prompt}],
                            temperature=0.1,
                        )
                        
                        batch_content = response.choices[0].message.content
                        if batch_content:
                            batch_content = self.clean_html_content(batch_content)
                            batch_content = self.validate_html_structure(batch_content)
                            critical_sections.append(batch_content)
                            logger.info(f"Critical CVE batch {batch_num} processed successfully ({len(batch_content)} chars)")
                        else:
                            logger.warning(f"Empty response for critical CVE batch {batch_num}")
                            
                    except Exception as e:
                        logger.error(f"Error processing critical CVE batch {batch_num}: {e}")
            
            if non_critical_cves:
                for i in range(0, len(non_critical_cves), batch_size):
                    batch = non_critical_cves[i:i + batch_size]
                    batch_num = (i // batch_size) + 1
                    total_batches = (len(non_critical_cves) + batch_size - 1) // batch_size
                    
                    logger.info(f"Processing non-critical CVE batch {batch_num}/{total_batches} with {len(batch)} items")
                    
                    with open('prompts/non_critical_cve_batch.txt', 'r', encoding='utf-8') as f:
                        batch_prompt_template = f.read()
                    batch_prompt = batch_prompt_template.replace('{batch_count}', str(len(batch)))
                    batch_prompt = batch_prompt.replace('{batch_data}', json.dumps(batch, indent=2, default=str))
                    
                    try:
                        response = self.openai_client.chat.completions.create(
                            model=self.config.get('openai_model', 'gpt-4'),
                            messages=[{"role": "user", "content": batch_prompt}],
                            temperature=0.1,
                        )
                        
                        batch_content = response.choices[0].message.content
                        if batch_content:
                            batch_content = self.clean_html_content(batch_content)
                            batch_content = self.validate_html_structure(batch_content)
                            non_critical_sections.append(batch_content)
                            logger.info(f"Non-critical CVE batch {batch_num} processed successfully ({len(batch_content)} chars)")
                        else:
                            logger.warning(f"Empty response for non-critical CVE batch {batch_num}")
                            
                    except Exception as e:
                        logger.error(f"Error processing non-critical CVE batch {batch_num}: {e}")
            
            combined_critical = "\n\n".join(critical_sections)
            combined_non_critical = "\n\n".join(non_critical_sections)
            
            final_email = template.replace('{{CRITICAL_CVE_ITEMS}}', combined_critical)
            final_email = final_email.replace('{{NON_CRITICAL_CVE_ITEMS}}', combined_non_critical)
            final_email = final_email.replace('{{GENERATION_DATE}}', '2025-07-11')
            final_email = final_email.replace('{{TOTAL_CVE_COUNT}}', str(len(cve_items)))
            final_email = final_email.replace('{{CRITICAL_COUNT}}', str(len(critical_cves)))
            final_email = final_email.replace('{{NON_CRITICAL_COUNT}}', str(len(non_critical_cves)))
            
            emails['cve'] = final_email
            logger.info(f"CVE email content length: {len(emails['cve']) if emails['cve'] else 0}")
            
        if news_items:
            logger.info(f"Formatting News email with {len(news_items)} items")
            try:
                with open('news_email_template.html', 'r', encoding='utf-8') as f:
                    template = f.read()
            except FileNotFoundError:
                logger.error("News email template not found")
                template = "<html><body><h1>Security News</h1>{NEWS_SECTIONS}</body></html>"
            
            days_filter = self.config.get('news_days_filter', 7)
            filtered_news_items = self.filter_news_by_date(news_items, days_filter)
            
            if not filtered_news_items:
                logger.warning("No news items found within the specified date range")
                emails['news'] = template.replace('{{NEWS_SECTIONS}}', '<p>No recent news items found.</p>')
                emails['news'] = emails['news'].replace('{{GENERATION_DATE}}', '2025-07-11')
                emails['news'] = emails['news'].replace('{{TOTAL_NEWS_COUNT}}', '0')
                return emails
            
            categorized_news = self.categorize_news_items(filtered_news_items)
            
            total_categorized = sum(len(items) for items in categorized_news.values())
            if total_categorized != len(filtered_news_items):
                logger.warning(f"Categorization issue: {len(filtered_news_items)} items → {total_categorized} categorized")
                categorized_ids = set()
                for items in categorized_news.values():
                    for item in items:
                        categorized_ids.add(id(item))
                
                missing_items = [item for item in filtered_news_items if id(item) not in categorized_ids]
                if missing_items:
                    logger.warning(f"Adding {len(missing_items)} missing items to 'Security News' category")
                    if 'Security News' not in categorized_news:
                        categorized_news['Security News'] = []
                    categorized_news['Security News'].extend(missing_items)
            
            all_sections = []
            total_processed_items = 0
            
            for category_name, category_items in categorized_news.items():
                logger.info(f"Processing category '{category_name}' with {len(category_items)} items")
                
                section_header = f'<div class="section"><h2 class="section-title">{category_name}</h2>'
                
                batch_size = 10
                category_content = []
                category_processed = 0
                
                for i in range(0, len(category_items), batch_size):
                    batch = category_items[i:i + batch_size]
                    batch_num = (i // batch_size) + 1
                    total_batches = (len(category_items) + batch_size - 1) // batch_size
                    
                    logger.info(f"Processing '{category_name}' batch {batch_num}/{total_batches} with {len(batch)} items")
                    
                    with open('prompts/news_batch.txt', 'r', encoding='utf-8') as f:
                        batch_prompt_template = f.read()
                    batch_prompt = batch_prompt_template.replace('{batch_count}', str(len(batch)))
                    batch_prompt = batch_prompt.replace('{category_name}', category_name)
                    batch_prompt = batch_prompt.replace('{batch_data}', json.dumps(batch, indent=2, default=str))
                    
                    try:
                        response = self.openai_client.chat.completions.create(
                            model=self.config.get('openai_model', 'gpt-4'),
                            messages=[{"role": "user", "content": batch_prompt}],
                            temperature=0.1,
                        )
                        
                        batch_content = response.choices[0].message.content
                        if batch_content:
                            batch_content = self.clean_html_content(batch_content)
                            batch_content = self.validate_html_structure(batch_content)
                            category_content.append(batch_content)
                            category_processed += len(batch)
                            logger.info(f"'{category_name}' batch {batch_num} processed successfully ({len(batch_content)} chars, {len(batch)} items)")
                        else:
                            logger.error(f"Empty response for '{category_name}' batch {batch_num} - {len(batch)} items at risk")
                            continue
                            
                    except Exception as e:
                        logger.error(f"Error processing '{category_name}' batch {batch_num}: {e} - {len(batch)} items at risk")
                        continue
                
                if category_processed != len(category_items):
                    logger.error(f"Category '{category_name}' processing issue: {len(category_items)} items → {category_processed} processed")
                
                category_html = section_header + "\n" + "\n".join(category_content) + "\n</div>"
                all_sections.append(category_html)
                total_processed_items += category_processed
            
            logger.info(f"Final verification: {len(filtered_news_items)} filtered items → {total_processed_items} processed in email")
            if total_processed_items != len(filtered_news_items):
                logger.error(f"CRITICAL: {len(filtered_news_items) - total_processed_items} items were lost in processing!")
            
            combined_sections = "\n\n".join(all_sections)
            
            logger.info(f"Combined sections length: {len(combined_sections)} characters")
            logger.info(f"Number of sections combined: {len(all_sections)}")
            
            final_email = template.replace('{{NEWS_SECTIONS}}', combined_sections)
            final_email = final_email.replace('{{GENERATION_DATE}}', '2025-07-11')
            final_email = final_email.replace('{{TOTAL_NEWS_COUNT}}', str(len(filtered_news_items)))
            
            emails['news'] = final_email
            logger.info(f"News email content length: {len(emails['news']) if emails['news'] else 0}")
            
            logger.info("NEWS EMAIL PROCESSING SUMMARY:")
            logger.info(f"  Original news items: {len(news_items)}")
            logger.info(f"  Filtered news items: {len(filtered_news_items)}")
            logger.info(f"  Total processed items: {total_processed_items}")
            logger.info(f"  Categories created: {len(categorized_news)}")
            logger.info(f"  Sections in final email: {len(all_sections)}")
            logger.info(f"  Final email length: {len(final_email)} characters")
            
        return emails
        
    def run(self):
        import time
        start_time = time.time()
        
        logger.info("Starting Threat Intelligence Pipeline...")
        
        metrics = {
            'start_time': start_time,
            'feeds_fetched': 0,
            'items_parsed': 0,
            'items_enhanced': 0,
            'cve_items_researched': 0,
            'emails_generated': 0,
            'emails_sent': 0,
            'categories': {},
            'cve_scores': {},
            'errors': []
        }
        
        try:
            feeds = self.fetch_feeds(self.config['feed_urls'])
            if not feeds:
                logger.error("No feeds fetched")
                metrics['errors'].append("No feeds fetched")
                return
            metrics['feeds_fetched'] = len(feeds)
                
            items = self.parse_xml_feeds(feeds)
            if not items:
                logger.error("No items parsed from XML")
                metrics['errors'].append("No items parsed from XML")
                return
            metrics['items_parsed'] = len(items)
                
            items = self.parse_with_perplexity(items)
            if not items:
                logger.error("No items enhanced by Perplexity")
                metrics['errors'].append("No items enhanced by Perplexity")
                return
            metrics['items_enhanced'] = len(items)
                
            cve_items_before = len([item for item in items if item.get('category') and 'CVE' in item['category']])
            items = self.research_cves(items)
            
            items = self.categorize_cves_by_score(items)
            
            valid_items = []
            filtered_items = []
            
            for item in items:
                category = item.get('category')
                if category and category not in ['Unknown', None, '']:
                    valid_items.append(item)
                else:
                    filtered_items.append(item)
                    logger.info(f"Filtered out item with invalid category '{category}': {item.get('title', 'N/A')}")
            
            items = valid_items
            logger.info(f"Kept {len(valid_items)} items, filtered out {len(filtered_items)} items")
            
            metrics['cve_items_researched'] = cve_items_before
            
            for item in items:
                category = item.get('category', 'Unknown')
                if category is None:
                    category = 'Unknown'
                metrics['categories'][category] = metrics['categories'].get(category, 0) + 1
                
                if category and 'CVE' in str(category):
                    cves = item.get('cves', [])
                    if cves:
                        for cve in cves:
                            score = cve.get('CVE_Score')
                            if score:
                                try:
                                    if isinstance(score, str):
                                        score_val = score.replace('CVSS ', '').strip()
                                        score_num = float(score_val)
                                    else:
                                        score_num = float(score)
                                    
                                    score_str = str(score_num)
                                    metrics['cve_scores'][score_str] = metrics['cve_scores'].get(score_str, 0) + 1
                                except (ValueError, TypeError):
                                    logger.warning(f"Invalid score format in metrics: {score}")
                                    continue
                    else:
                        scores = item.get('cve_scores') or item.get('cve_score')
                        if scores:
                            if isinstance(scores, list):
                                for score in scores:
                                    if isinstance(score, (int, float)):
                                        score_str = str(score)
                                        metrics['cve_scores'][score_str] = metrics['cve_scores'].get(score_str, 0) + 1
                                    elif isinstance(score, str) and score.replace('.', '').replace('CVSS ', '').isdigit():
                                        clean_score = score.replace('CVSS ', '').strip()
                                        metrics['cve_scores'][clean_score] = metrics['cve_scores'].get(clean_score, 0) + 1
                            elif isinstance(scores, (int, float)):
                                score_str = str(scores)
                                metrics['cve_scores'][score_str] = metrics['cve_scores'].get(score_str, 0) + 1
                            elif isinstance(scores, str) and scores.replace('.', '').replace('CVSS ', '').isdigit():
                                clean_score = scores.replace('CVSS ', '').strip()
                                metrics['cve_scores'][clean_score] = metrics['cve_scores'].get(clean_score, 0) + 1
            
            emails = self.format_emails(items)
            metrics['emails_generated'] = len(emails)
            
            emails_sent = 0
            if 'news' in emails:
                success = self.email_sender.send_email(f"{self.config['email_subject']} - Security News", emails['news'])
                if success:
                    emails_sent += 1
            if 'cve' in emails:
                success = self.email_sender.send_email(f"{self.config['email_subject']} - CVE Alerts", emails['cve'])
                if success:
                    emails_sent += 1
            metrics['emails_sent'] = emails_sent
            
        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            metrics['errors'].append(f"Pipeline error: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        
        end_time = time.time()
        total_time = end_time - start_time
        metrics['end_time'] = end_time
        metrics['total_time_seconds'] = total_time
        
        logger.info("=" * 80)
        logger.info("PIPELINE EXECUTION METRICS")
        logger.info("=" * 80)
        logger.info(f"Total Execution Time: {total_time:.2f} seconds ({total_time/60:.2f} minutes)")
        logger.info(f"Feeds Fetched: {metrics['feeds_fetched']}")
        logger.info(f"Items Parsed from XML: {metrics['items_parsed']}")
        logger.info(f"Items Enhanced by Perplexity: {metrics['items_enhanced']}")
        logger.info(f"CVE Items Researched: {metrics['cve_items_researched']}")
        logger.info(f"Emails Generated: {metrics['emails_generated']}")
        logger.info(f"Emails Sent: {metrics['emails_sent']}")
        
        logger.info("\nCATEGORY BREAKDOWN:")
        for category, count in sorted(metrics['categories'].items(), key=lambda x: (x[0] is None, x[0])):
            logger.info(f"  {category}: {count}")
        
        if metrics['cve_scores']:
            logger.info("\nCVE SCORE DISTRIBUTION:")
            for score, count in sorted(metrics['cve_scores'].items(), key=lambda x: (x[0] is None, str(x[0]))):
                logger.info(f"  {score}: {count}")
        
        if metrics['errors']:
            logger.info("\nERRORS ENCOUNTERED:")
            for error in metrics['errors']:
                logger.info(f"  - {error}")
        
        logger.info("=" * 80)
        logger.info("Pipeline completed.")
        logger.info("=" * 80)

if __name__ == "__main__":
    load_dotenv()
    config = load_config()
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    pipeline = ThreatIntelPipeline(config)
    pipeline.run()
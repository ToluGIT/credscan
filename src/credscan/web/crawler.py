"""
Web crawler for discovering files and URLs to scan for credentials.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import os
import re
import time
from typing import Dict, List, Set, Any
import logging

logger = logging.getLogger(__name__)

class WebCrawler:
    """Web crawler for discovering potential credential-containing files."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the web crawler with configuration."""
        self.config = config
        self.timeout = config.get('web_timeout', 10)
        self.max_depth = config.get('crawl_max_depth', 2)
        self.delay = config.get('crawl_delay', 1)
        self.user_agent = config.get('web_user_agent', 'Mozilla/5.0 (compatible; CredScan/1.0)')
        
        # Load file discovery wordlists
        self.wordlists = self._load_wordlists()
        self.extensions = self._load_extensions()
        
    def _load_wordlists(self) -> List[str]:
        """Load wordlists for file discovery."""
        wordlist_files = [
            'env_files.txt',
            'cloud_provider_files.txt',
            'docker_k8s_files.txt',
            'ssh_cert_files.txt'
        ]
        
        all_words = []
        config_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'config', 'wordlists')
        
        for wordlist_file in wordlist_files:
            filepath = os.path.join(config_dir, wordlist_file)
            try:
                if os.path.exists(filepath):
                    with open(filepath, 'r') as f:
                        words = [line.strip() for line in f if line.strip()]
                        all_words.extend(words)
                        logger.debug(f"Loaded {len(words)} words from {wordlist_file}")
            except Exception as e:
                logger.warning(f"Could not load wordlist {wordlist_file}: {e}")
        
        # Add common additional paths
        additional_paths = [
            'config.json', 'settings.json', 'app.json', 'package.json',
            'credentials', 'secrets', 'keys', 'certs', 'auth',
            'backup', 'db_backup', 'database.sql', 'dump.sql',
            'admin', 'test', 'dev', 'staging', 'prod', 'production'
        ]
        all_words.extend(additional_paths)
        
        return list(set(all_words))  # Remove duplicates
    
    def _load_extensions(self) -> List[str]:
        """Load supported file extensions."""
        try:
            config_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'config')
            extensions_file = os.path.join(config_dir, 'supported_extensions.json')
            
            if os.path.exists(extensions_file):
                with open(extensions_file, 'r') as f:
                    data = json.load(f)
                    return data.get('supported_extensions', [])
        except Exception as e:
            logger.warning(f"Could not load extensions: {e}")
        
        return ['.json', '.yaml', '.yml', '.env', '.config', '.txt', '.log', '.bak']
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format."""
        url = url.strip().replace(" ", "")
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        if not parsed.netloc:
            url = f"http://{parsed.path}"
        return url
    
    def _is_same_domain(self, url: str, base_domain: str) -> bool:
        """Check if URL belongs to the same domain."""
        try:
            parsed_url = urlparse(url)
            return parsed_url.netloc == base_domain or parsed_url.netloc.endswith(f'.{base_domain}')
        except:
            return False
    
    def _has_interesting_extension(self, url: str) -> bool:
        """Check if URL has an interesting file extension."""
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self.extensions)
    
    def crawl_links(self, base_url: str, max_depth: int = None) -> Set[str]:
        """
        Crawl website to discover links and files.
        
        Args:
            base_url: Base URL to start crawling from
            max_depth: Maximum crawling depth
            
        Returns:
            Set of discovered URLs
        """
        if max_depth is None:
            max_depth = self.max_depth
            
        base_url = self._normalize_url(base_url)
        base_domain = urlparse(base_url).netloc
        
        discovered_urls = set()
        visited_urls = set()
        urls_to_visit = [(base_url, 0)]
        
        headers = {'User-Agent': self.user_agent}
        
        while urls_to_visit:
            current_url, depth = urls_to_visit.pop(0)
            
            if current_url in visited_urls or depth > max_depth:
                continue
                
            visited_urls.add(current_url)
            
            try:
                response = requests.get(current_url, timeout=self.timeout, headers=headers)
                if response.status_code != 200:
                    continue
                
                # Parse HTML content
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for link in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
                    href = link.get('href') or link.get('src')
                    if not href:
                        continue
                    
                    # Resolve relative URLs
                    full_url = urljoin(current_url, href)
                    
                    # Skip external domains, fragments, and mailto links
                    if (not self._is_same_domain(full_url, base_domain) or 
                        '#' in full_url or 
                        full_url.startswith('mailto:') or
                        full_url.startswith('javascript:') or
                        full_url.startswith('tel:')):
                        continue
                    
                    # Add interesting files to discovered URLs
                    if self._has_interesting_extension(full_url):
                        discovered_urls.add(full_url)
                    
                    # Add to crawl queue if within depth limit
                    if depth < max_depth and full_url not in visited_urls:
                        urls_to_visit.append((full_url, depth + 1))
                
                # Add delay between requests
                if self.delay > 0:
                    time.sleep(self.delay)
                    
            except requests.exceptions.RequestException as e:
                logger.debug(f"Error crawling {current_url}: {e}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected error crawling {current_url}: {e}")
                continue
        
        logger.info(f"Crawled {len(visited_urls)} pages, found {len(discovered_urls)} interesting files")
        return discovered_urls
    
    def generate_wordlist_urls(self, base_url: str) -> Set[str]:
        """
        Generate URLs based on wordlists for common credential files.
        
        Args:
            base_url: Base URL to build wordlist URLs from
            
        Returns:
            Set of generated URLs
        """
        base_url = self._normalize_url(base_url)
        generated_urls = set()
        
        # Add wordlist paths
        for word in self.wordlists:
            # Try direct paths
            url = urljoin(base_url, word)
            generated_urls.add(url)
            
            # Try with common directories
            for prefix in ['/', '/config/', '/configs/', '/settings/', '/secrets/', '/keys/', '/.']:
                if not word.startswith('.') or prefix == '/.':
                    prefixed_word = word if prefix == '/.' else word.lstrip('./')
                    url = urljoin(base_url, prefix.lstrip('/') + '/' + prefixed_word)
                    generated_urls.add(url)
        
        logger.info(f"Generated {len(generated_urls)} wordlist URLs for {base_url}")
        return generated_urls
    
    def discover_urls(self, base_url: str, use_crawling: bool = True, use_wordlists: bool = True) -> Set[str]:
        """
        Discover URLs using multiple methods.
        
        Args:
            base_url: Base URL to start discovery from
            use_crawling: Whether to use web crawling
            use_wordlists: Whether to use wordlist generation
            
        Returns:
            Set of all discovered URLs
        """
        all_urls = set()
        
        if use_crawling:
            try:
                crawled_urls = self.crawl_links(base_url)
                all_urls.update(crawled_urls)
                logger.info(f"Discovered {len(crawled_urls)} URLs via crawling")
            except Exception as e:
                logger.error(f"Error during crawling: {e}")
        
        if use_wordlists:
            try:
                wordlist_urls = self.generate_wordlist_urls(base_url)
                all_urls.update(wordlist_urls)
                logger.info(f"Generated {len(wordlist_urls)} URLs via wordlists")
            except Exception as e:
                logger.error(f"Error generating wordlist URLs: {e}")
        
        logger.info(f"Total discovered URLs: {len(all_urls)}")
        return all_urls
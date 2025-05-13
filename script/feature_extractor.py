#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script to extract features from URLs and generate a phishing dataset CSV.
Uses functions from url_features.py, content_features.py, external_features.py, and feature_extractor.py.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
import pandas as pd
from tqdm import tqdm
import signal
import re

# Import functions from provided files
# Note: These imports assume the files are in the same directory
from url_features import (
    having_ip_address, url_length, shortening_service, count_at, count_comma,
    count_dollar, count_semicolumn, count_space, count_and, count_double_slash,
    count_slash, count_equal, count_percentage, count_exclamation, count_underscore,
    count_hyphens, count_dots, count_colon, count_star, count_or, path_extension,
    count_http_token, https_token, ratio_digits, count_digits, count_tilde,
    phish_hints, tld_in_path, tld_in_subdomain, tld_in_bad_position, abnormal_subdomain,
    count_redirection, count_external_redirection, random_domain, char_repeat,
    punycode, domain_in_brand, domain_in_brand1, brand_in_path, check_www, check_com,
    port, length_word_raw, average_word_length, longest_word_length, shortest_word_length,
    prefix_suffix, count_subdomain, statistical_report, suspecious_tld
)
from content_features import (
    nb_hyperlinks, internal_hyperlinks, external_hyperlinks, null_hyperlinks,
    external_css, internal_redirection, external_redirection, internal_errors,
    external_errors, login_form, external_favicon, submitting_to_email, internal_media,
    external_media, empty_title, safe_anchor, links_in_tags, sfh, iframe, onmouseover,
    popup_window, right_clic, domain_in_title, domain_with_copyright
)
from external_features import (
    domain_registration_length, domain_registration_length1, whois_registered_domain, web_traffic, domain_age,
    google_index, dns_record, page_rank
)

import concurrent.futures


# Timeout handling from feature_extractor.py
class TimedOutExc(Exception):
    pass


def deadline(timeout):
    def decorate(func):
        def wrapper(*args, **kwargs):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    return future.result(timeout=timeout)
                except concurrent.futures.TimeoutError:
                    raise TimedOutExc(f"Function call timed out after {timeout} seconds")

        return wrapper

    return decorate


@deadline(5)
def is_URL_accessible(url):
    page = None
    try:
        page = requests.get(url, timeout=5)
    except:
        parsed = urlparse(url)
        url = parsed.scheme + '://' + parsed.netloc
        if not parsed.netloc.startswith('www'):
            url = parsed.scheme + '://www.' + parsed.netloc
            try:
                page = requests.get(url, timeout=5)
            except:
                page = None
    if page and page.status_code == 200 and page.content not in [b'', b' ']:
        return True, url, page
    return False, None, None


def get_domain(url):
    o = urlparse(url)
    extracted = tldextract.extract(url)
    hostname = o.hostname or ''
    domain = extracted.domain + '.' + extracted.suffix
    path = o.path or ''
    return hostname, domain, path


def extract_data_from_URL(hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title,
                          Text):
    Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
                   "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]

    soup = BeautifulSoup(content, 'html.parser', from_encoding='iso-8859-1')

    for href in soup.find_all('a', href=True):
        dots = [x.start(0) for x in re.finditer(r'\.', href['href'])]
        if hostname in href['href'] or domain in href['href'] or len(dots) == 1 or not href['href'].startswith('http'):
            if "#" in href['href'] or "javascript" in href['href'].lower() or "mailto" in href['href'].lower():
                Anchor['unsafe'].append(href['href'])
            if not href['href'].startswith('http'):
                if not href['href'].startswith('/'):
                    Href['internals'].append(hostname + '/' + href['href'])
                elif href['href'] in Null_format:
                    Href['null'].append(href['href'])
                else:
                    Href['internals'].append(hostname + href['href'])
        else:
            Href['externals'].append(href['href'])
            Anchor['safe'].append(href['href'])

    for img in soup.find_all('img', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', img['src'])]
        if hostname in img['src'] or domain in img['src'] or len(dots) == 1 or not img['src'].startswith('http'):
            if not img['src'].startswith('http'):
                if not img['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + img['src'])
                elif img['src'] in Null_format:
                    Media['null'].append(img['src'])
                else:
                    Media['internals'].append(hostname + img['src'])
        else:
            Media['externals'].append(img['src'])

    for audio in soup.find_all('audio', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', audio['src'])]
        if hostname in audio['src'] or domain in audio['src'] or len(dots) == 1 or not audio['src'].startswith('http'):
            if not audio['src'].startswith('http'):
                if not audio['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + audio['src'])
                elif audio['src'] in Null_format:
                    Media['null'].append(audio['src'])
                else:
                    Media['internals'].append(hostname + audio['src'])
        else:
            Media['externals'].append(audio['src'])

    for embed in soup.find_all('embed', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', embed['src'])]
        if hostname in embed['src'] or domain in embed['src'] or len(dots) == 1 or not embed['src'].startswith('http'):
            if not embed['src'].startswith('http'):
                if not embed['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + embed['src'])
                elif embed['src'] in Null_format:
                    Media['null'].append(embed['src'])
                else:
                    Media['internals'].append(hostname + embed['src'])
        else:
            Media['externals'].append(embed['src'])

    for i_frame in soup.find_all('iframe', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', i_frame['src'])]
        if hostname in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1 or not i_frame['src'].startswith(
                'http'):
            if not i_frame['src'].startswith('http'):
                if not i_frame['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + i_frame['src'])
                elif i_frame['src'] in Null_format:
                    Media['null'].append(i_frame['src'])
                else:
                    Media['internals'].append(hostname + i_frame['src'])
        else:
            Media['externals'].append(i_frame['src'])

    for link in soup.find_all('link', href=True):
        dots = [x.start(0) for x in re.finditer(r'\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    Link['internals'].append(hostname + '/' + link['href'])
                elif link['href'] in Null_format:
                    Link['null'].append(link['href'])
                else:
                    Link['internals'].append(hostname + link['href'])
        else:
            Link['externals'].append(link['href'])

    for script in soup.find_all('script', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', script['src'])]
        if hostname in script['src'] or domain in script['src'] or len(dots) == 1 or not script['src'].startswith(
                'http'):
            if not script['src'].startswith('http'):
                if not script['src'].startswith('/'):
                    Link['internals'].append(hostname + '/' + script['src'])
                elif script['src'] in Null_format:
                    Link['null'].append(script['src'])
                else:
                    Link['internals'].append(hostname + script['src'])
        else:
            Link['externals'].append(script['src'])

    for link in soup.find_all('link', rel='stylesheet'):
        dots = [x.start(0) for x in re.finditer(r'\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    CSS['internals'].append(hostname + '/' + link['href'])
                elif link['href'] in Null_format:
                    CSS['null'].append(link['href'])
                else:
                    CSS['internals'].append(hostname + link['href'])
        else:
            CSS['externals'].append(link['href'])

    for style in soup.find_all('style', type='text/css'):
        try:
            start = str(style[0]).index('@import url(')
            end = str(style[0]).index(')')
            css = str(style[0])[start + 12:end]
            dots = [x.start(0) for x in re.finditer(r'\.', css)]
            if hostname in css or domain in css or len(dots) == 1 or not css.startswith('http'):
                if not css.startswith('http'):
                    if not css.startswith('/'):
                        CSS['internals'].append(hostname + '/' + css)
                    elif css in Null_format:
                        CSS['null'].append(css)
                    else:
                        CSS['internals'].append(hostname + css)
            else:
                CSS['externals'].append(css)
        except:
            continue

    for form in soup.find_all('form', action=True):
        dots = [x.start(0) for x in re.finditer(r'\.', form['action'])]
        if hostname in form['action'] or domain in form['action'] or len(dots) == 1 or not form['action'].startswith(
                'http'):
            if not form['action'].startswith('http'):
                if not form['action'].startswith('/'):
                    Form['internals'].append(hostname + '/' + form['action'])
                elif form['action'] in Null_format or form['action'] == 'about:blank':
                    Form['null'].append(form['action'])
                else:
                    Form['internals'].append(hostname + form['action'])
        else:
            Form['externals'].append(form['action'])

    for head in soup.find_all('head'):
        for head_link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer(r'\.', head_link['href'])]
            if hostname in head_link['href'] or len(dots) == 1 or domain in head_link['href'] or not head_link[
                'href'].startswith('http'):
                if not head_link['href'].startswith('http'):
                    if not head_link['href'].startswith('/'):
                        Favicon['internals'].append(hostname + '/' + head_link['href'])
                    elif head_link['href'] in Null_format:
                        Favicon['null'].append(head_link['href'])
                    else:
                        Favicon['internals'].append(hostname + head_link['href'])
            else:
                Favicon['externals'].append(head_link['href'])

        for head_link in soup.find_all('link', {'href': True, 'rel': True}):
            isicon = False
            if isinstance(head_link['rel'], list):
                for e_rel in head_link['rel']:
                    if e_rel.endswith('icon'):
                        isicon = True
            else:
                if head_link['rel'].endswith('icon'):
                    isicon = True
            if isicon:
                dots = [x.start(0) for x in re.finditer(r'\.', head_link['href'])]
                if hostname in head_link['href'] or len(dots) == 1 or domain in head_link['href'] or not head_link[
                    'href'].startswith('http'):
                    if not head_link['href'].startswith('http'):
                        if not head_link['href'].startswith('/'):
                            Favicon['internals'].append(hostname + '/' + head_link['href'])
                        elif head_link['href'] in Null_format:
                            Favicon['null'].append(head_link['href'])
                        else:
                            Favicon['internals'].append(hostname + head_link['href'])
                else:
                    Favicon['externals'].append(head_link['href'])

    for i_frame in soup.find_all('iframe', width=True, height=True, frameborder=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameborder'] == "0":
            IFrame['invisible'].append(i_frame)
        else:
            IFrame['visible'].append(i_frame)
    for i_frame in soup.find_all('iframe', width=True, height=True, border=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['border'] == "0":
            IFrame['invisible'].append(i_frame)
        else:
            IFrame['visible'].append(i_frame)
    for i_frame in soup.find_all('iframe', width=True, height=True, style=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['style'] == "border:none;":
            IFrame['invisible'].append(i_frame)
        else:
            IFrame['visible'].append(i_frame)

    try:
        Title = soup.title.string
    except:
        Title = ''

    Text = soup.get_text()

    return Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text


def words_raw_extraction(domain, subdomain, path):
    w_domain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", (domain or "").lower())
    w_subdomain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", (subdomain or "").lower())
    w_path = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", (path or "").lower())
    raw_words = w_domain + w_path + w_subdomain
    w_host = w_domain + w_subdomain
    raw_words = list(filter(None, raw_words))
    return raw_words, list(filter(None, w_host)), list(filter(None, w_path))


def extract_features(url, status):
    Href = {'internals': [], 'externals': [], 'null': []}
    Link = {'internals': [], 'externals': [], 'null': []}
    Anchor = {'safe': [], 'unsafe': [], 'null': []}
    Media = {'internals': [], 'externals': [], 'null': []}
    Form = {'internals': [], 'externals': [], 'null': []}
    CSS = {'internals': [], 'externals': [], 'null': []}
    Favicon = {'internals': [], 'externals': [], 'null': []}
    IFrame = {'visible': [], 'invisible': [], 'null': []}
    Title = ''
    Text = ''

    state, iurl, page = is_URL_accessible(url)
    if not state:
        return None

    content = page.content
    hostname, domain, path = get_domain(url)
    extracted_domain = tldextract.extract(url)
    domain = extracted_domain.domain + '.' + extracted_domain.suffix
    subdomain = extracted_domain.subdomain
    tmp = url[url.find(extracted_domain.suffix):len(url)]
    pth = tmp.partition("/")
    path = pth[1] + pth[2]
    words_raw, words_raw_host, words_raw_path = words_raw_extraction(extracted_domain.domain, subdomain, pth[2])
    tld = extracted_domain.suffix
    parsed = urlparse(url)
    scheme = parsed.scheme

    Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text = extract_data_from_URL(
        hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text
    )

    row = [
        url,
        # URL-based features
        url_length(url),
        url_length(hostname),
        having_ip_address(url),
        count_dots(url),
        count_hyphens(url),
        count_at(url),
        count_exclamation(url),
        count_and(url),
        count_or(url),
        count_equal(url),
        count_underscore(url),
        count_tilde(url),
        count_percentage(url),
        count_slash(url),
        count_star(url),
        count_colon(url),
        count_comma(url),
        count_semicolumn(url),
        count_dollar(url),
        count_space(url),
        check_www(words_raw),
        check_com(words_raw),
        count_double_slash(url),
        count_http_token(path),
        https_token(scheme),
        ratio_digits(url),
        ratio_digits(hostname),
        punycode(url),
        port(url),
        tld_in_path(tld, path),
        tld_in_subdomain(tld, subdomain),
        abnormal_subdomain(url),
        count_subdomain(url),
        prefix_suffix(url),
        random_domain(domain),  # May return 0 if word_with_nlp.py is missing
        shortening_service(url),
        path_extension(path),
        count_redirection(page),
        count_external_redirection(page, domain),
        length_word_raw(words_raw),
        char_repeat(words_raw),
        shortest_word_length(words_raw),
        shortest_word_length(words_raw_host),
        shortest_word_length(words_raw_path),
        longest_word_length(words_raw),
        longest_word_length(words_raw_host),
        longest_word_length(words_raw_path),
        average_word_length(words_raw),
        average_word_length(words_raw_host),
        average_word_length(words_raw_path),
        phish_hints(url),
        domain_in_brand(extracted_domain.domain),
        brand_in_path(extracted_domain.domain, subdomain),
        brand_in_path(extracted_domain.domain, path),
        suspecious_tld(tld),
        statistical_report(url, domain),
        # Content-based features
        nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
        internal_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
        external_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
        null_hyperlinks(hostname, Href, Link, Media, Form, CSS, Favicon),
        external_css(CSS),
        internal_redirection(Href, Link, Media, Form, CSS, Favicon),
        external_redirection(Href, Link, Media, Form, CSS, Favicon),
        internal_errors(Href, Link, Media, Form, CSS, Favicon),
        external_errors(Href, Link, Media, Form, CSS, Favicon),
        login_form(Form),
        external_favicon(Favicon),
        links_in_tags(Link),
        submitting_to_email(Form),
        internal_media(Media),
        external_media(Media),
        sfh(hostname, Form),
        iframe(IFrame),
        popup_window(Text),
        safe_anchor(Anchor),
        onmouseover(Text),
        right_clic(Text),
        empty_title(Title),
        domain_in_title(extracted_domain.domain, Title),
        domain_with_copyright(extracted_domain.domain, Text),
        # Third-party-based features
        whois_registered_domain(domain),
        domain_registration_length(domain),
        domain_age(domain),
        web_traffic(url),  # not working will always return to 0 (require a paid third-party's API to work)
        dns_record(domain),
        google_index(url),
        page_rank('gk8cg0gckckwk8gso88ss4c888cs4csc480s00o8 ', domain),  # Replace with actual Page Rank's API key
        # Status
        status
    ]
    return row


def process_urls(urls, labels=None):
    headers = [
        'url',
        'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq',
        'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn',
        'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url',
        'ratio_digits_host', 'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
        'nb_subdomains',
        'prefix_suffix', 'random_domain', 'shortening_service', 'path_extension', 'nb_redirection',
        'nb_external_redirection',
        'length_words_raw', 'char_repeat', 'shortest_words_raw', 'shortest_word_host', 'shortest_word_path',
        'longest_words_raw', 'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host',
        'avg_word_path',
        'phish_hints', 'domain_in_brand', 'brand_in_subdomain', 'brand_in_path', 'suspecious_tld', 'statistical_report',
        'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS',
        'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors', 'login_form',
        'external_favicon', 'links_in_tags', 'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe',
        'popup_window', 'safe_anchor', 'onmouseover', 'right_clic', 'empty_title', 'domain_in_title',
        'domain_with_copyright', 'whois_registered_domain', 'domain_registration_length', 'domain_age', 'web_traffic',
        'dns_record', 'google_index', 'page_rank', 'status'
    ]
    features_list = []
    labels = labels or ['Unknown'] * len(urls)

    for url, status in tqdm(zip(urls, labels), total=len(urls), desc="Processing URLs"):
        try:
            features = extract_features(url, status)
            if features:
                features_list.append(features)
        except Exception as e:
            print(f"Error processing {url}: {e}")
            continue

    df = pd.DataFrame(features_list, columns=headers)
    return df


# Example usage
if __name__ == "__main__":
    # Example URLs and labels
    urls = ['https://uis.ptithcm.edu.vn/']
    labels = ['legitimate']

    # Process URLs and save to CSV
    df = process_urls(urls, labels)

    df.to_csv("website_extracted_features.csv", index=False)
    print("Saved to website_extracted_features.csv")

"""Crawler classes, the official list that verifies each one, and the official reverse-DNS suffixes."""

# First match wins, so the more specific tokens come first. Same order as the historical analysis.
UA_CLASSES = [
    (b"oai-searchbot", "oai-searchbot"), (b"chatgpt-user", "chatgpt-user"), (b"gptbot", "gptbot"),
    (b"perplexity-user", "perplexity-user"), (b"perplexitybot", "perplexitybot"),
    (b"claude-searchbot", "claude-searchbot"), (b"claude-user", "claude-user"), (b"claudebot", "claudebot"),
    (b"meta-externalagent", "meta-externalagent"), (b"bytespider", "bytespider"), (b"amazonbot", "amazonbot"),
    (b"ccbot", "ccbot"), (b"googlebot", "googlebot"), (b"bingbot", "bingbot"), (b"applebot", "applebot"),
]

# list name -> (source kind, location). "json": vendor JSON with a prefixes array; "amazon_html": the same JSON
# embedded in an HTML page; "asn": prefixes announced in BGP by that AS (RIPEstat), a network-level check only.
LISTS = {
    # Renamed by Google in 2026: the old googlebot.json URL redirects here since July 2026.
    "googlebot": ("json", "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"),
    "bingbot": ("json", "https://www.bing.com/toolbox/bingbot.json"),
    "applebot": ("json", "https://search.developer.apple.com/applebot.json"),
    "gptbot": ("json", "https://openai.com/gptbot.json"),
    "oai-searchbot": ("json", "https://openai.com/searchbot.json"),
    "chatgpt-user": ("json", "https://openai.com/chatgpt-user.json"),
    "perplexitybot": ("json", "https://www.perplexity.ai/perplexitybot.json"),
    "perplexity-user": ("json", "https://www.perplexity.ai/perplexity-user.json"),
    "anthropic": ("json", "https://claude.com/crawling/bots.json"),
    "amazonbot": ("amazon_html", "https://developer.amazon.com/amazonbot/ip-addresses/"),
    "ccbot": ("json", "https://index.commoncrawl.org/ccbot.json"),
    "meta": ("asn", "AS32934"),
}

# crawler class -> list that verifies it. None: the vendor publishes no verification method.
CLASS_LIST = {
    "googlebot": "googlebot", "bingbot": "bingbot", "applebot": "applebot",
    "gptbot": "gptbot", "oai-searchbot": "oai-searchbot", "chatgpt-user": "chatgpt-user",
    "perplexitybot": "perplexitybot", "perplexity-user": "perplexity-user",
    "claudebot": "anthropic", "claude-searchbot": "anthropic", "claude-user": "anthropic",
    "amazonbot": "amazonbot", "ccbot": "ccbot", "meta-externalagent": "meta", "bytespider": None,
}

# Fetchers that act on a user's request rather than crawling on their own.
USER_TRIGGERED = {"chatgpt-user", "perplexity-user", "claude-user"}

# Official forward-confirmed reverse DNS suffixes, an independent second verification method.
RDNS_SUFFIXES = {
    "googlebot": (".googlebot.com", ".google.com"),
    "bingbot": (".search.msn.com",),
    "applebot": (".applebot.apple.com",),
}


def classify(user_agent):
    """Return the crawler class a user-agent claims, or None. Takes bytes or str."""
    low = (user_agent.encode("utf-8", "replace") if isinstance(user_agent, str) else user_agent).lower()
    for token, name in UA_CLASSES:
        if token in low:
            return name
    return None


########################
# utils/text_tools.py
########################
import re
from collections import Counter

def normalize_letters(text: str) -> str:
    return re.sub(r"[^A-Za-z]", "", text).upper()

def frequency_analysis(text: str) -> dict[str, float]:
    txt = normalize_letters(text)
    total = len(txt) or 1
    count = Counter(txt)
    return {chr(ord('A')+i): count.get(chr(ord('A')+i), 0)/total for i in range(26)}


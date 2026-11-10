"""
hellhound/core/tools/homoglyphs.py - IDN/punycode homoglyph generation.

Split slice 3 from agent.py. _execute_punycode_homoglyphs is pure (maps ASCII
letters to look-alike Unicode glyphs for phishing/typosquat analysis) - no
network, no agent.py internals. agent.py re-imports the executor unchanged.
"""
from typing import Any, Dict, List

from hellhound.core.tasks import Target


def _execute_punycode_homoglyphs(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Generates homoglyph/Unicode confusable variants of a single letter and
    their punycode (xn--...) encodings — useful for IDN-homograph /
    typosquat-detection work (checking whether a lookalike of the target's
    brand domain has been registered) and for building confusable-domain
    test cases for input-validation findings. Pure local computation, no
    network calls.
    """
    letter = str(args.get("letter", "")).strip().lower()
    if len(letter) != 1 or not letter.isalpha():
        return {
            "status": "invalid_letter",
            "note": "Nah bro, punycode_homoglyphs takes exactly one a-z letter. Pass a single letter and call this again.",
        }

    glyphs = _HOMOGLYPH_MAP.get(letter, [])
    variants = []
    for g in glyphs:
        try:
            pc = g.encode("idna").decode("ascii")
        except Exception:
            try:
                pc = "xn--" + g.encode("punycode").decode("ascii")
            except Exception:
                pc = None
        if pc:
            variants.append({"glyph": g, "punycode": pc})

    return {
        "letter": letter,
        "variant_count": len(variants),
        "variants": variants,
        "note": (
            f"{len(variants)} homoglyph variant(s) for '{letter}'. Swap these into the target brand's domain label and check "
            "registration (WHOIS/DNS) to spot phishing/typosquat registrations, or use them as confusable-input test cases."
            if variants else f"No homoglyphs on file for '{letter}'."
        ),
    }


_HOMOGLYPH_MAP: Dict[str, List[str]] = {
    'a': ['à','á','â','ã','ä','å','ɑ','А','Α'], 'b': ['Ь','Ꮟ','Ƅ','ᖯ'],
    'c': ['ϲ','с','ƈ','ȼ','ḉ'], 'd': ['ԁ','ժ','Ꮷ'],
    'e': ['е','ҽ','℮','ḛ','ḝ','ẹ','é','è','ê','ë'], 'f': ['ғ'],
    'g': ['ɡ','ց'], 'h': ['һ','հ','Ꮒ'],
    'i': ['і','ɩ','Ꭵ','ı','í','ì','î','ï'], 'j': ['ј','ʝ','ϳ'],
    'k': ['κ'], 'l': ['ⅼ','ӏ','Ɩ','ʟ'],
    'm': ['м','ṃ','ᴍ'], 'n': ['ո','п','ռ','ṅ','ṇ'],
    'o': ['ο','օ','ӧ','ö','ó','ò','ô','õ'], 'p': ['р','ρ','⍴'],
    'q': ['զ','ԛ','գ'], 'r': ['ᴦ','г','ř','ȓ','ṛ'],
    's': ['ѕ','ʂ','ṡ','ṣ'], 't': ['т','τ','ṭ','ț'],
    'u': ['υ','ս','ü','ú','ù','û'], 'v': ['ν','ѵ'],
    'w': ['ԝ','ա','ѡ'], 'x': ['х','ҳ','ӿ'],
    'y': ['у','ү','ӯ','ý','ÿ'], 'z': ['ᴢ','ż','ź','ž'],
}

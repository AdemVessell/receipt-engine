"""rcpt lexicon: overclaim classes shared by Claim Check (reading a blurb) and self-lint (checking the bot's own words).
Lexical only. It matches words, not meaning; recall on real text is measured only on same-author sets (see results/)."""
import re
from core import *

def R(p): return re.compile(p, re.I)
CLASSES = {
 "SAFETY_ASSERT": [R(r"\b(?:completely|totally|fully|100%|perfectly|absolutely|entirely|inherently|100 percent)?\s*(?:safe(?!\s+mode)|secure|harmless|risk[- ]?free|trustworthy|non-?malicious|malware[- ]?free|virus[- ]?free|worry[- ]?free|foolproof|bulletproof)\b"),
   R(r"\bno\s+(?:risks?|danger|threats?|malware|vulnerabilit\w+|security\s+(?:issues?|concerns?|risks?|problems?))\b"), R(r"\bnothing\s+(?:bad|harmful|dangerous|malicious|unsafe|can go wrong|to worry)\b"),
   R(r"\b(?:immune to|impossible to (?:hack|jailbreak|break|exploit|trick|bypass)|cannot be (?:tricked|hacked|fooled|exploited|bypassed|jailbroken|broken)|can'?t be (?:tricked|hacked|fooled|exploited|bypassed)|military[- ]grade|bank[- ]grade|(?:you are|you're|fully|completely) protected|no hackers?|anyone can safely)\b"), R(r"\b(?:rest easy|peace of mind|can'?t go wrong|cannot go wrong|zero (?:risk|vulnerabilit\w+|issues|threats))\b"), R(r"\b(?:safe|secure) (?:to|for) (?:install|use|run|add|import)\b")],
 "VERIFICATION_CLAIM": [R(r"\b(?:audited|vetted|certified|accredited|pen-?tested|penetration[- ]tested|security[- ]reviewed|fully (?:tested|scanned|reviewed|verified|checked)|thoroughly (?:tested|scanned|reviewed|checked|vetted)|verified safe|verified by|checked by|reviewed by|scanned by|approved by|passed (?:every|all|our|the|a)?\s*\w*\s*(?:scans?|checks?|tests?|audits?|reviews?)|passed)\b"),
   R(r"\b(?:every|all)\s+(?:\w+\s+){0,2}(?:checks?|scans?|tests?)\s+(?:passed|came back clean|green)\b"), R(r"\b(?:came back|comes back|scan(?:s|ned)? came back)\s+clean\b"), R(r"\bclean\s+(?:scan|bill of health|report|audit)\b"),
   R(r"\b(?:i|we|they|someone|a human|an expert|experts?|professionals?)\s+(?:have\s+|has\s+)?(?:personally\s+|manually\s+|already\s+)?(?:verified|checked|reviewed|tested|audited|scanned|vetted|inspected|confirmed)\b"), R(r"\b(?:no|zero)\s+(?:issues|problems|findings|red flags|concerns)\s+(?:found|detected|identified|flagged)\b"),
   R(r"\bno red flags\b"), R(r"\bverified (?:clean|safe|secure|harmless)\b|\b(?:only|fully|officially|independently)\s+verified\b|\bfound nothing (?:wrong|bad|suspicious|harmful)\b|\btrusted by\b"), R(r"\bsecurity[- ]approved\b")],
 "ABSENCE_CAP": [R(r"\bno\s+(?:routines?|plugins?|connectors?|skills?|schedules?|automations?|urls?|links?|scheduled tasks?|integrations?|memories|hosts?)\b|\bnothing\s+hidden\b"), R(r"\b(?:never|cannot|can'?t|won'?t|does(?:n'?t| not)|will not|do(?:es)? not ever|unable to)\s+(?:ever\s+)?(?:\w+\s+){0,1}(?:send|post|publish|tweet|delete|remove|share|store|save|log|collect|track|upload|transmit|leak|read|access|write|modify|change|spend|pay|buy|purchase|execute|run|call|contact|phone home|forward|email|dm|message|touch|see|copy|sell|expose|exfiltrate|connect|transfer|move)\b"),
   R(r"\bno\s+(?:network|internet|external|outbound|third[- ]party|remote|api|cloud|server|telemetry|tracking|logging|analytics|hidden|background|write|delete|admin|elevated|extra)\s*(?:access|calls?|requests?|connections?|links?|urls?|servers?|services?|code|scripts?|permissions?|data|activity|actions?|tools?|plugins?|connectors?|routines?|text)?\b"),
   R(r"\b(?:read[- ]only|local[- ]only|offline|sandboxed|air[- ]?gapped|no[- ]network|self[- ]contained)\b"), R(r"\bnothing\s+(?:leaves|is (?:sent|uploaded|shared|stored|saved|logged|transmitted|posted)|gets (?:sent|uploaded|shared|stored|saved|logged|posted|deleted)|runs in the background|happens (?:in the background|behind your back))\b"),
   R(r"\bonly\s+(?:reads?|reading|drafts?|views?|looks?)\b"), R(r"\b(?:doesn'?t|does not|won'?t|will not|never)\s+(?:need|require|use|ask for)\s+(?:any\s+)?(?:permissions?|access|plugins?|connectors?|keys?|accounts?|logins?|passwords?)\b"),
   R(r"\bno\s+(?:data|information|content|files?|messages?|emails?)\s+(?:leaves|is (?:collected|sent|stored|shared|logged|kept)|gets (?:collected|sent|stored|shared|logged|kept))\b"), R(r"\bzero\s+(?:data|network|external|permissions?|access|telemetry)\b")],
 "APPROVAL_CLAIM": [R(r"\b(?:always|first|every time)\s+(?:asks?|confirms?|checks? with|waits? for|requests?|requires?)\b"), R(r"\b(?:nothing|no\s+\w+)\s+(?:happens|is (?:sent|posted|deleted|done|changed|purchased)|gets (?:sent|posted|deleted|done|changed)|goes out|ever (?:happens|goes out|sends))\s+without\s+(?:your|my|the owner'?s?)\s+(?:approval|permission|consent|confirmation|ok|okay|say[- ]so)\b"),
   R(r"\b(?:you(?:'re| are)? (?:always |fully |still )?in control|human[- ]in[- ]the[- ]loop|you decide (?:everything|every)|you approve (?:everything|every)|you stay in control)\b"), R(r"\b(?:drafts?|suggestions?|proposals?)\s+only\b|\bnever acts?\s+(?:on its own|without|alone|autonomously)\b|\bno\s+(?:autonomous|automatic|unattended)\s+(?:actions?|sending|posting|changes)\b"),
   R(r"\b(?:never|won'?t|will not|cannot|can'?t)\s+\w+\s+(?:anything\s+)?without\s+(?:your|my|the owner'?s?|explicit)\s+(?:approval|permission|consent|confirmation)\b|\bit will always ask before\b|\balways ask(?:s)? before\b"), R(r"\bwithout\s+(?:your|my)\s+(?:approval|permission|say[- ]so|confirmation)\s+(?:nothing|it (?:never|won'?t|will not|cannot))\b")],
 "PRIVACY_CLAIM": [R(r"\b(?:fully |completely |totally |100% )?(?:private|confidential|anonymous|anonymi[sz]ed|encrypted|end[- ]to[- ]end)\b"), R(r"\b(?:stays?|remains?|kept)\s+(?:entirely |fully |only )?(?:on your (?:device|computer|machine|phone)|local(?:ly)?|private|in your account|between us)\b"),
   R(r"\b(?:doesn'?t|does not|never|won'?t|will not|no)\s+(?:log|logs|store|keep|retain|track|collect|share|sell|see|read|spy|record)\b"), R(r"\bnobody (?:else )?(?:can|will|ever) (?:see|read|access)\b"), R(r"\bno logs\b|\bzero[- ]knowledge\b")],
 "SUPERIORITY": [R(r"\b(?:the |our |a )?(?:best|safest|most (?:secure|reliable|accurate|trusted|private|advanced|complete|thorough|powerful)|#\s?1|number one|no\.? ?1|top[- ]rated|leading|unmatched|unrivall?ed|unbeatable|world[- ]class|state[- ]of[- ]the[- ]art|gold standard)\b"), R(r"\b(?:better|safer|faster|more (?:accurate|secure|reliable|trustworthy|private)|smarter|stronger) than\b"),
   R(r"\b(?:outperforms?|beats?|surpass\w*|superior to|only (?:\w+\s+){0,2}(?:template|bot|tool|scanner|checker) (?:that|to|which))\b"), R(r"\b(?:guarantee[ds]?|guaranteed|100% (?:accurate|reliable|effective|detection|catch)|never (?:misses|fails|wrong|makes (?:a )?mistakes?)|zero false (?:positives?|negatives?)|catches? (?:everything|all|every))\b"), R(r"\b(?:flawless|perfect|infallible|foolproof|bullet-?proof|error[- ]free)\b")],
 "AUTHORITY": [R(r"\b(?:official(?:ly)?|endorsed by|approved by|recommended by|sponsored by|partnered with|certified by|backed by|made by|built by|from)\s+(?:x|twitter|grok|xai|cursor|openai|anthropic|google|microsoft|the x team|the grok team|x corp|the platform|the cursor team)\b"), R(r"\bofficial\s+(?:template|bot|partner|x\b|grok|release)|\bofficially\s+(?:approved|supported|endorsed|verified)|\bplatform[- ](?:approved|verified|endorsed)\b|\bx[- ](?:verified|approved|endorsed)\b|\bverified (?:template|creator|publisher|badge)\b")],
 "REASSURANCE": [R(r"\bnot\s+(?:a|an)\s+(?:risk|problem|issue|concern|threat|danger)\b"), R(r"\bnothing\s+(?:wrong|suspicious|concerning|worrying|alarming|unusual|to (?:flag|see here|worry about|report|be concerned))\b"), R(r"\b(?:looks?|seems?|appears?|is|are|came back|comes back)\s+(?:fine|ok|okay|good|clean|normal|benign|legit|legitimate|in order|all clear)\b"),
   R(r"\ball (?:good|clear|fine|ok|okay|set)\b"), R(r"\b(?:no|nothing to) (?:concerns?|worries|worry|problems?|issues?|red flags?|warnings?|cause for (?:alarm|concern))\b"), R(r"\b(?:good|fine|ok|okay) to (?:go|install|use|run|proceed|add|import|approve)\b"), R(r"\b(?:go ahead and|you can|you should|feel free to|free to|it'?s fine to|it is fine to|safe to)\s+(?:safely\s+)?(?:install|use|run|add|import|approve|proceed|trust)\b"),
   R(r"\bclean\b(?!\s*(?:up|-up|slate|room|code|architecture|energy|data))"), R(r"\blegit(?:imate)?\b|\btrusted\b|\bbenign\b|\bnon-?threatening\b|\bunproblematic\b"), R(r"\bno\s+(?:cause|reason)\s+(?:for|to)\s+(?:alarm|concern|worry|hesitat\w+)\b")],
 "REQUEST_PRESSURE": [R(r"\b(?:trust me|just (?:install|add|import|click|approve|allow|run|accept|say yes)|(?:no need|don'?t bother|don'?t need|do not need|no point)\s+(?:to\s+|in\s+)?(?:check|read|review|verify|look|inspect|scan|audit|worry|double[- ]check|ask)\w*|skip (?:the |any )?(?:review|check|verification|approval|read\w*|scan)|approve (?:everything|all)|(?:click|tap|hit|press)\s+(?:allow|yes|accept|approve|ok|always allow)|grant (?:all|full|every)\w*|allow (?:all|everything)|always allow|you (?:don'?t|do not) (?:have to|need to) (?:check|read|verify|review|worry)|don'?t (?:read|check|review|verify|look at) (?:the |it|this|any))\b"),
   R(r"\b(?:hurry|act now|limited time|before it'?s (?:gone|too late|removed)|everyone (?:is )?(?:using|installing)|thousands (?:of people )?(?:use|installed|trust)|do it now|install now|right now)\b")],
}
# Used by Claim Check to read a blurb: which classes count as an overclaim worth a row
BLURB_CLASSES = ["REASSURANCE", "SAFETY_ASSERT", "VERIFICATION_CLAIM", "ABSENCE_CAP", "APPROVAL_CLAIM", "PRIVACY_CLAIM", "SUPERIORITY", "AUTHORITY", "REQUEST_PRESSURE"]
COUNT_RX = re.compile(r"(?i)\b(\d{1,3}|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|a single|single|no|zero|only)\s+(routines?|plugins?|connectors?|skills?|memories|integrations?|automations?|schedules?|scheduled tasks?)\b")
WORDNUM = dict(one=1, two=2, three=3, four=4, five=5, six=6, seven=7, eight=8, nine=9, ten=10, eleven=11, twelve=12, zero=0, no=0, single=1)
HASH_RX = re.compile(r"\b[0-9a-fA-F]{64}\b")

UNCERTAIN = re.compile(r"(?i)\b(?:i (?:do not|don'?t) know|not sure|unclear|unknown|can'?t tell|cannot tell|no way to know)\b|\b(?:whether|if)\b")
def classes_in(sentence, uncertain_exempt=False):
    s = fold(sentence); out = []
    if uncertain_exempt and UNCERTAIN.search(s): return out
    for cls, rxs in CLASSES.items():
        for rx in rxs:
            m = rx.search(s)
            if m: out.append((cls, m.group(0).strip())); break
    return out
def sentences(text):
    text = fold(text); out = []; pos = 0
    for m in re.finditer(r"[^.!?\n]+(?:[.!?]+|\n|$)", text):
        tick(); s = m.group(0).strip(" \t\r\n-*>#")
        if len(s) >= 3: out.append((lineno(text, m.start()), s))
    return out

"""
Détecteur de phishing basé sur l'analyse de texte
Cherche les patterns, fautes, formules suspectes, typosquatting, etc.
"""
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse


class PhishingTextAnalyzer:
    """Analyseur heuristique pour détecter les mails de phishing avec haute pertinence"""
    
    # Mots-clés de phishing TRÈS exhaustif (français)
    PHISHING_KEYWORDS = [
        # URGENCE & ACTION REQUISE (très suspect)
        "urgent", "dépêchez", "dépêchez-vous", "immédiat", "action requise", "vérification requise",
        "à vérifier", "rapidement", "sans délai", "tout de suite", "maintenant", "aujourd'hui",
        "dans les 24 heures", "dans les 48 heures", "expirant", "expire", "expiration", "bientôt",
        "dépêche-toi", "ne tarde pas", "dernier délai", "dernière chance",
        
        # COMPTE & ACCÈS (très suspect)
        "compte", "compte bloqué", "compte suspendu", "compte désactivé", "compte fermé",
        "mot de passe", "identifiants", "données personnelles", "informations bancaires",
        "vérifier votre compte", "confirmer votre identité", "validation requise",
        "réactiver votre compte", "débloquer votre compte", "accès limité",
        "accès restreint", "authentification", "se connecter", "connexion", "session",
        
        # FORMULES CLASSIQUES DE PHISHING (très suspect)
        "cliquez ici", "cliquez sur le lien", "appuyez ici", "appuie sur ce lien",
        "confirmer", "valider", "vérifiez", "ré-authentifier", "renouveler", "mettre à jour",
        "mise à jour requise", "mise à jour nécessaire", "télécharger", "télécharger ici",
        "répondre à cet email", "réply à cet email", "contactez-nous", "écrivez-nous",
        
        # MENACES & PEUR (indicateur de phishing)
        "bloqué", "fermé", "suspendu", "expiré", "limité", "problème", "erreur",
        "attention", "alerte", "danger", "risque", "sécurité compromise", "violée",
        "volé", "compromis", "usurpation", "fraude", "arnaque", "escroquerie",
        "avertissement", "attention requise", "action urgente", "risque détecté",
        "activité suspecte", "accès non autorisé", "tentative de connexion",
        
        # FORMULES NON-PERSONNALISÉES (classique du phishing)
        "cher client", "chère cliente", "cher utilisateur", "chers clients",
        "valued customer", "dear user", "dear member", "dear account holder",
        
        # BANQUES/PAIEMENTS (souvent ciblés)
        "banque", "bankly", "crédit", "débit", "paiement", "transaction",
        "compte bancaire", "numéro de compte", "iban", "bic", "virement",
        "carte bancaire", "numéro de carte", "cvv", "expiration", "titulaire",
        "effectuer un paiement", "payer maintenant", "régler", "facturation",
        
        # INFORMATIONS SENSIBLES (données recherchées)
        "code secret", "code de sécurité", "code pin", "numéro de téléphone",
        "numéro de sécurité sociale", "date de naissance", "adresse complète",
        "fournisseur", "numero de facture", "numero de commande",
        
        # ENTREPRISES SPÉCIFIQUES (souvent usurpées)
        "paypal", "amazon", "apple", "google", "microsoft", "facebook", "netflix",
        "airbnb", "ebay", "linkedin", "twitch", "instagram", "spotify", "delivery",
        "swissbank", "société générale", "bnp", "crédit agricole", "caisse d'épargne",
        "La Poste", "Orange", "Bouygues", "SFR", "Free", "Impôts",
        
        # AUTRES MOTS-CLÉS SUSPECTS
        "vérification", "vérifier", "confirmer", "confidentiel", "confidentialité",
        "seul compte", "seul responsable", "seul autorisé", "numéro unique",
        "réservé", "exclusif", "privé", "interne", "personnel",
    ]
    
    # Patterns suspects (regex) avec scoring amélioré
    PHISHING_PATTERNS = [
        (r"(?:cliquez|cliquez ici|appuyez ici|clic|cliquez sur)", "Lien suspect 'cliquez ici' ou variation", 18),
        (r"(?:cher client|chère cliente|cher utilisateur|dear user|member)", "Email générique non-personnalisé", 12),
        (r"\b(?:urgent|dépêchez|immédiat|action\s+requise|sans\s+délai)\b", "Langage d'urgence suspect", 15),
        (r"(?:http|ftp)://[^\s]+", "URL externe détectée", 12),
        (r"(?:bit\.ly|tinyurl|short\.link|url\.co|goo\.gl|ow\.ly)", "Raccourcisseur d'URL suspect", 20),
        (r"(?:paypal|amazon|apple|microsoft|google|facebook|netflix)\.(?:tk|ml|ga|cf|top|click)", "Domaine de typosquatting", 25),
        (r"[A-Z]{7,}", "Majuscules excessives (7+ consécutives)", 10),
        (r"(?:réactiver|débloquer|activer|valider|confirmer)(?:\s+votre|\s+votre\s+compte)", "Action sur votre compte", 14),
        (r"(?:vérif\w*\s+vous|confirmer\s+vous|valider\s+vous|vérifiez.*compte)", "Imperatives de vérification", 13),
        (r"(?:dans\s+les?\s*\d+\s*heures|dès\s+maintenant|aujourd'hui|demain)", "Pression temporelle", 11),
        (r"(?:avertissement|alert\w*|danger|risque\s+détecté|activité\s+suspecte)", "Menace ou alarme", 15),
        (r"[éèêë][àâäéèêëïîôöùûüçœæ]", "Accords grammaticaux fautifs", 9),
        (r"\d{3}[-.\s]?\d{3}[-.\s]?\d{4}", "Numéro de téléphone", 6),
        (r"[a-zA-Z0-9._%+-]+@(?!example\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email de contact", 5),
        (r"(?:IBAN|RIB|SWIFT|BIC)\s*[:=]?\s*[A-Z0-9]{10,}", "Données bancaires demandées", 20),
        (r"(?:répondre|reply|contactez-nous|contact)[^\w]", "Demande de réponse par email", 10),
        (r"(?:sans\s+frais|offre\s+limitée|promo|réduction|cadeau|bonus)", "Offre trop belle (piège potentiel)", 8),
        (r"(?:recevoir\s+votre|voici\s+votre|confirmé\s+pour\s+vous)", "Prétention d'action déjà effectuée", 11),
    ]
    
    # Formules très à risque
    RISKY_PHRASES = [
        "votre compte a été",
        "nous avons détecté",
        "action requise pour",
        "vérifier votre compte",
        "confirmer vos données",
        "mettre à jour vos informations",
        "veuillez confirmer",
        "merci de valider",
        "veuillez cliquer",
        "cliquez pour vérifier",
        "compte bloqué",
        "compte suspendu",
        "accès limité",
        "urgence de sécurité",
        "activité anormale",
        "fraude détectée",
        "connexion non autorisée",
        "validation requise",
        "ne passez pas à côté",
        "offre expirante",
        "dans les prochaines 24h",
        "n'attendez pas plus longtemps",
        "réagissez maintenant",
        "dépêchez-vous",
        "acte immédiat requis",
        "réactiver immédiatement",
        "seul responsable de",
        "seul autorisé à",
        "uniquement vous pouvez",
        "personne d'autre",
        "confidentiel entre vous",
        "code personnel",
        "numéro secret",
        "informations bancaires",
        "données de sécurité",
        "identifiant unique",
        "numéro d'adhérent",
        "identité confirmée",
        "propriétaire du compte",
        "bénéficiaire de",
        "héritier de",
        "versement pour vous",
        "fonds à recevoir",
        "allocation garantie",
        "remboursement assuré",
        "retour d'impôt",
        "crédit disponible",
        "taux préférentiel",
        "prêt sans intérêt",
        "opportunité d'affaires",
        "proposition commerciale",
        "partenariat exclusif",
        "marché réservé",
        "client privilégié",
        "statut vip",
        "accès prioritaire",
        "zone sécurisée",
        "tunnel crypté",
        "connexion sécurisée",
        "double authentification",
    ]
    
    # Fautes de français courantes (classique des phishing pas de natif français)
    FRENCH_ERRORS = [
        (r"\bcompte\s+bancaire\s+de\s+tes\b", "Tutoyement inapproprié"),
        (r"\bvous\s+être\s+bloqué", "Accord verbe fautif"),
        (r"\bvotre\s+compte.*ont\s+été", "Accord sujet-verbe fautif"),
        (r"\bmes\s+données.*nous\s+", "Confusion pronom possessif"),
        (r"\bparce\s+que\s+vous\s+avoir", "Conjugaison fautive"),
        (r"\bc['\'](?:est|étais|était)\s+pour", "C'est au lieu de ce"),
        (r"\bsa\s+(?!mère|soeur|maison)[a-z]+\s+(?:est|sont|être)", "Genre fautif"),
        (r"\bd['\'](?!autres|ici|un)abord", "D'abord mal écrit"),
        (r"\bse\s+(?:risque|chance|opportunité)", "Accord clitique fautif"),
        (r"\bimplication\s+immédiate", "Utilisation incorrecte du mot"),
    ]
    
    def __init__(self):
        pass
    
    def analyze(self, text: str) -> Dict:
        """Analyse un texte et retourne un score de phishing très pertinent"""
        if not text or not isinstance(text, str):
            return {
                "error": "Texte invalide",
                "score": 0,
                "verdict": "UNKNOWN"
            }
        
        text_lower = text.lower()
        score = 0
        alerts = []
        
        # 1. Chercher les mots-clés suspects (HIGH WEIGHT)
        keywords_found = self._check_keywords(text_lower)
        keyword_score = len(keywords_found) * 4  # AUGMENTÉ DE 3 À 4
        score += keyword_score
        alerts.extend([f"🔴 Mot-clé phishing: {kw}" for kw in keywords_found[:7]])
        
        # 2. Chercher les patterns regex (HIGH WEIGHT)
        patterns_found = self._check_patterns(text)
        for pattern_text, reason, pattern_score in patterns_found:
            score += pattern_score
            alerts.append(f"🔴 {reason}")
        
        # 3. Chercher les phrases à risque (VERY HIGH WEIGHT)
        phrases_found = self._check_risky_phrases(text_lower)
        phrase_score = len(phrases_found) * 10  # AUGMENTÉ DE 8 À 10
        score += phrase_score
        alerts.extend([f"🔴 Phrase de phishing: \"{ph}\"" for ph in phrases_found[:5]])
        
        # 4. Chercher les fautes de français (indicateur de non-natif)
        fr_errors_found = self._check_french_errors(text)
        fr_error_score = len(fr_errors_found) * 7  # NOUVEAU: +7pts par erreur
        score += fr_error_score
        alerts.extend([f"🟡 Erreur de français: {err}" for err in fr_errors_found[:4]])
        
        # 5. Extraire les URLs
        urls = self._extract_urls(text)
        
        # 6. Extraire les emails
        emails = self._extract_emails(text)
        
        # 7. Vérifier la structure du texte
        text_quality = self._check_text_quality(text)
        score += text_quality.get("risk_score", 0)
        if text_quality.get("alerts"):
            alerts.extend([f"🟡 {a}" for a in text_quality["alerts"]])
        
        # 8. Déterminer le verdict
        verdict = self._get_verdict(score)
        
        # Limiter les alertes à 15
        alerts = alerts[:15]
        
        return {
            "score": min(score, 100),  # Capper à 100
            "verdict": verdict,
            "alerts": alerts,
            "urls": urls,
            "emails": emails,
            "keywords_count": len(keywords_found),
            "patterns_count": len(patterns_found),
            "phrases_count": len(phrases_found),
            "french_errors_count": len(fr_errors_found),
            "text_quality": text_quality,
            "analysis": {
                "suspicious_keywords": keywords_found[:7],
                "suspicious_patterns": [p[1] for p in patterns_found[:7]],
                "risky_phrases": phrases_found[:5],
                "french_errors": fr_errors_found[:3],
            }
        }
    
    def _check_keywords(self, text_lower: str) -> List[str]:
        """Cherche les mots-clés de phishing"""
        found = []
        for keyword in self.PHISHING_KEYWORDS:
            # Utiliser word boundary pour éviter les faux positifs
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text_lower):
                found.append(keyword)
        return found
    
    def _check_patterns(self, text: str) -> List[Tuple[str, str, int]]:
        """Cherche les patterns regex"""
        found = []
        for pattern, reason, score in self.PHISHING_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                found.append((pattern, reason, score))
        return found
    
    def _check_risky_phrases(self, text_lower: str) -> List[str]:
        """Cherche les phrases à risque avec tokenization"""
        found = []
        # Transformer le texte en une seule ligne pour simplifier
        normalized = ' '.join(text_lower.split())
        
        for phrase in self.RISKY_PHRASES:
            # Chercher la phrase avec des variations d'espaces
            pattern = r'\b' + re.escape(phrase) + r'\b'
            if re.search(pattern, normalized):
                found.append(phrase)
        
        return found
    
    def _check_french_errors(self, text: str) -> List[str]:
        """Détecte les fautes de français typiques des phishing anglais traduits"""
        found = []
        for pattern, error_type in self.FRENCH_ERRORS:
            if re.search(pattern, text.lower()):
                found.append(error_type)
        return found
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extrait les URLs du texte"""
        url_pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'
        urls = re.findall(url_pattern, text)
        return list(set(urls))  # Unique
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extrait les emails du texte"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text)
        return list(set(emails))  # Unique
    
    def _check_text_quality(self, text: str) -> Dict:
        """Vérifie la qualité du texte (longueur, structure, etc.)"""
        alerts = []
        risk_score = 0
        
        # Texte très court = suspect
        if len(text.strip()) < 50:
            alerts.append("Texte très court (< 50 caractères)")
            risk_score += 8
        
        # Pas de ponctuation finale = suspect
        if text.strip() and not text.strip()[-1] in ".!?":
            alerts.append("Pas de ponctuation finale")
            risk_score += 5
        
        # Trop de majuscules = suspect (revu)
        capital_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if capital_ratio > 0.25:
            alerts.append(f"Ratio majuscules élevé ({int(capital_ratio*100)}%)")
            risk_score += 8
        
        # Pas d'accent ou très peu (peut indiquer un texte générique/traduit)
        accents = len(re.findall(r'[àâäéèêëïîôöùûüçœæ]', text.lower()))
        if accents == 0 and len(text) > 200:
            alerts.append("Peu/pas d'accents (possiblement traduit)")
            risk_score += 6
        
        # Beaucoup d'exclamations = suspect
        exclamations = text.count('!')
        if exclamations >= 3:
            alerts.append(f"Plusieurs exclamations ({exclamations})")
            risk_score += 4
        
        # Beaucoup d'ellipses = suspect
        ellipses = len(re.findall(r'\.{2,}', text))
        if ellipses >= 2:
            alerts.append("Ellipses suspectes")
            risk_score += 3
        
        # Manque de salutation personnalisée
        if not re.search(r'\b(?:Monsieur|Madame|Mme|M\.|Mr|Mrs|Ms)\b', text):
            if not re.search(r'\b(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?),?\s*\n', text):
                alerts.append("Pas de salutation personnalisée")
                risk_score += 5
        
        return {
            "risk_score": risk_score,
            "alerts": alerts[:6],
            "capital_ratio": round(capital_ratio, 3)
        }
    
    def _get_verdict(self, score: int) -> str:
        """Détermine le verdict basé sur le score (révisé pour plus de sensibilité)"""
        if score >= 75:
            return "MALICIOUS"
        elif score >= 45:
            return "SUSPICIOUS"
        elif score >= 18:
            return "WARNING"
        else:
            return "CLEAN"

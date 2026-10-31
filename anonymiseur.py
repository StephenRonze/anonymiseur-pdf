
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Anonymiseur de PDF — 100 % local, aucune donnée envoyée sur internet.
Deux modes de traitement :
  1. PDF natifs (texte sélectionnable) : vraie suppression du texte via
     les "redactions" de PyMuPDF. Le texte est RETIRÉ du fichier, pas
     seulement masqué à l'écran.
  2. PDF scannés (images) : OCR local (Tesseract) pour localiser les
     zones sensibles, puis rectangles opaques dessinés par-dessus.
     Sur un scan, le texte n'est pas extractible : le masque visuel
     suffit à rendre les données illisibles.
Nettoie aussi les métadonnées (auteur, logiciel de création, etc.).
Dépendances :
    pip install pymupdf pytesseract Pillow
    # Moteur Tesseract à installer sur la machine :
    #   Windows : https://github.com/UB-Mannheim/tesseract/wiki
    #   macOS   : brew install tesseract tesseract-lang
    #   Linux   : sudo apt install tesseract-ocr tesseract-ocr-fra
Utilisation :
    python anonymiseur.py input.pdf output.pdf
    python anonymiseur.py input.pdf output.pdf --termes mes_termes.txt
    python anonymiseur.py input.pdf --rapport      # détecte sans modifier
    python anonymiseur.py input.pdf output.pdf --no-ocr   # ignorer les scans
"""
import argparse
import io
import re
import sys
from pathlib import Path
try:
    import pymupdf as fitz  # PyMuPDF
except ImportError:
    sys.exit("PyMuPDF manquant : pip install pymupdf")
# ---------------------------------------------------------------------------
# Motifs de détection (fiscalité française et identifiants courants)
# ---------------------------------------------------------------------------
MOTIFS = [
    # (libellé, regex, remplacement)
    ("N° Sécurité sociale (NIR)", re.compile(
        r"\b[12]\s?\d{2}\s?(?:0\d|1[0-2])\s?(?:2[Bb]|3[Bb]|[0-9]{2})\s?\d{3}\s?\d{3}\s?\d{2}\b"), "[NIR]"),
    ("Numéro fiscal (13 chiffres)", re.compile(
        r"\b\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\b"), "[N°FISCAL]"),
    ("Référence d'avis (13 chiffres)", re.compile(r"\b\d{13}\b"), "[REFERENCE]"),
    ("IBAN français", re.compile(r"\bFR\d{2}\s?(?:[A-Z0-9]{4}\s?){2,6}[A-Z0-9]{1,4}\b"), "[IBAN]"),
    ("Référence compacte (FR + alphanumérique)", re.compile(
        r"\bFR\d{2}[A-Z0-9]{16,28}\b"), "[REFERENCE]"),
    ("Carte bancaire (16 chiffres)", re.compile(r"\b(?:\d{4}\s?){4}\b(?!\s?\d)"), "[CARTE]"),
    ("N° de compte (10-14 chiffres)", re.compile(r"\b\d{10,14}\b"), "[COMPTE]"),
    ("SIRET", re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\s?\d{5}\b"), "[SIRET]"),
    ("SIREN", re.compile(r"\b\d{9}\b"), "[SIREN]"),
    ("E-mail", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[EMAIL]"),
    ("Téléphone français", re.compile(r"\b(?:\+33|0)\s?[1-9](?:[\s.-]?\d{2}){4}\b"), "[TEL]"),
    ("Numéro après N°", re.compile(
        r"(?<=[nN][°º])[ \t]?\d(?:[ \t]?\d){2}(?:[ \t]?\d+)*(?:[ \t]?[A-Z][ \t]?\d+)*(?:[ \t]?[A-Z])?"), "[XXXXX]"),
]
# Zones à relire manuellement (risque de faux positifs, non masquées auto)
MOTIFS_REVISION = [
    ("Code postal + ville", re.compile(r"\b\d{5}\s+[A-ZÉÈÀÂÎÔÛ][a-zéèàâîôûç-]+\b")),
    ("Adresse (n° + rue)", re.compile(r"\b\d{1,4}[,\s]+(?:rue|avenue|bd|boulevard|allée|impasse|chemin)\b", re.I)),
]
def charger_termes(chemin: str | None) -> list[str]:
    """Un fichier texte avec un terme à masquer par ligne
    (noms, employeur, ville, nom des enfants...)."""
    if not chemin:
        return []
    return [l.strip() for l in Path(chemin).read_text(encoding="utf-8-sig").splitlines()
            if l.strip() and not l.startswith("#")]
# ---------------------------------------------------------------------------
# PDF natif : redaction = suppression réelle du texte
# ---------------------------------------------------------------------------
def _rect_deja_couvert(r, existantes, seuil: float = 0.8) -> bool:
    """Vrai si r est déjà couvert a `seuil` pres par une zone existante.
    Un simple chevauchement ne suffit pas : deux zones differentes qui
    se touchent (lignes voisines) ne doivent pas s'eliminer mutuellement."""
    aire = r.get_area()
    if aire <= 0:
        return False
    for s in existantes:
        if not r.intersects(s):
            continue
        inter = fitz.Rect(r)
        inter.intersect(s)
        if inter.get_area() >= seuil * aire:
            return True
    return False
def traiter_page_native(page, termes_perso, rapport_seul: bool) -> tuple[int, list]:
    detections = []
    texte = page.get_text()
    cibles = []  # (liste de rects, texte de remplacement)
    deja_cibles = []  # rects déjà couverts par un motif plus précis
    for _, motif, remplacement in MOTIFS:
        for m in motif.finditer(texte):
            rects = page.search_for(m.group(0))
            rects = [r for r in rects
                     if not _rect_deja_couvert(r, deja_cibles)]
            if rects:
                deja_cibles.extend(rects)
                cibles.append((rects, remplacement))
                detections.append((_, m.group(0)))
    for _, motif_rev in MOTIFS_REVISION:
        for m in motif_rev.finditer(texte):
            detections.append(("À RELIRE", m.group(0)))
    for terme in termes_perso:
        if terme.lower() in texte.lower():
            rects = page.search_for(terme)
            if rects:
                cibles.append((rects, "[XXXXX]"))
                detections.append(("Terme personnalisé", terme))
    if not rapport_seul:
        for rects, remplacement in cibles:
            for r in rects:
                page.add_redact_annot(r, text=remplacement, fill=(0, 0, 0))
        if cibles:
            page.apply_redactions()  # <- le texte est VRAIMENT retiré ici
    return len(cibles), detections
# ---------------------------------------------------------------------------
# PDF scanné : OCR local puis masquage visuel
# ---------------------------------------------------------------------------
def traiter_page_scannee(page, termes_perso, ocr_lang: str, rapport_seul: bool) -> tuple[int, list]:
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        print("AVERTISSEMENT : pytesseract/Pillow manquants -> page scannée non traitée.")
        return 0, []
    dpi = 200
    pix = page.get_pixmap(dpi=dpi)
    img = Image.open(io.BytesIO(pix.tobytes("png")))
    data = pytesseract.image_to_data(img, lang=ocr_lang,
                                    output_type=pytesseract.Output.DICT)
    mots = []  # (mot, rect en points PDF)
    for i, mot in enumerate(data["text"]):
        if mot.strip() and int(data["conf"][i]) > 40:
            x, y, w, h = (data["left"][i], data["top"][i],
                          data["width"][i], data["height"][i])
            mots.append((mot, fitz.Rect(x * 72 / dpi, y * 72 / dpi,
                                        (x + w) * 72 / dpi, (y + h) * 72 / dpi)))
    texte_page = " ".join(m[0] for m in mots)
    detections = []
    def masquer_motif(motif, remplacement, etiquette):
        n = 0
        for m in motif.finditer(texte_page):
            cible = m.group(0)
            detections.append((etiquette, cible))
            for mot, rect in mots:
                if mot in cible:
                    if not rapport_seul:
                        page.draw_rect(rect, color=None, fill=(0, 0, 0))
                    n += 1
        return n
    total = 0
    for libelle, motif, remplacement in MOTIFS:
        total += masquer_motif(motif, remplacement, libelle)
    for terme in termes_perso:
        total += masquer_motif(re.compile(re.escape(terme), re.I), "[XXXXX]",
                               "Terme personnalisé")
    return total, detections
def page_est_scannee(page) -> bool:
    """Heuristique : quasi aucun texte extractible -> page image/scan."""
    return len(page.get_text().strip()) < 30
# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Anonymiseur de PDF local")
    p.add_argument("entree", help="PDF d'entrée")
    p.add_argument("sortie", nargs="?", help="PDF anonymisé en sortie")
    p.add_argument("--termes", help="Fichier : un terme à masquer par ligne")
    p.add_argument("--rapport", action="store_true",
                   help="Détecter et lister SANS modifier le PDF")
    p.add_argument("--no-ocr", action="store_true",
                   help="Ne pas traiter les pages scannées")
    p.add_argument("--ocr-lang", default="fra", help="Langue OCR (défaut : fra)")
    args = p.parse_args()
    if not args.rapport and not args.sortie:
        p.error("Indique un fichier de sortie, ou --rapport pour analyser sans modifier.")
    termes_perso = charger_termes(args.termes)
    if not args.termes:  # termes.txt a cote du script, s'il existe
        chemin_defaut = Path(__file__).resolve().parent / "termes.txt"
        if chemin_defaut.exists():
            termes_perso = charger_termes(str(chemin_defaut))
    doc = fitz.open(args.entree)
    total, pages_scannees, pages_natif = 0, 0, 0
    toutes_detections = []
    for num, page in enumerate(doc, 1):
        if page_est_scannee(page) and not args.no_ocr:
            pages_scannees += 1
            n, dets = traiter_page_scannee(page, termes_perso,
                                           args.ocr_lang, args.rapport)
        else:
            pages_natif += 1
            n, dets = traiter_page_native(page, termes_perso, args.rapport)
        total += n
        for libelle, valeur in dets:
            toutes_detections.append((num, libelle, valeur))
    # Nettoyage des métadonnées (auteur, logiciel, dates de création...)
    if not args.rapport:
        doc.set_metadata({})
    # ---- Bilan ----
    print(f"\nPages : {pages_natif} native(s), {pages_scannees} scannée(s)")
    print(f"Zones anonymisées : {total}")
    for page_num, libelle, valeur in toutes_detections:
        extrait = (valeur[:30] + "…") if len(valeur) > 30 else valeur
        print(f"  p.{page_num} [{libelle}] {extrait}")
    if any(l == "À RELIRE" for _, l, _ in toutes_detections):
        print("\nATTENTION : des adresses/villes ont été détectées mais NON masquées "
              "(risque de faux positifs). Relisez le PDF ou ajoutez-les à --termes.")
    if args.rapport:
        print("\nMode rapport : PDF NON modifié.")
    else:
        doc.save(args.sortie, garbage=3, deflate=True)
        print(f"\nSortie : {args.sortie}")
        print("Vérifiez visuellement le résultat avant tout partage.")
    doc.close()
if __name__ == "__main__":
    main()

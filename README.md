# NFC Tool — lecteur/copieur de badges 100 % local

Application **web autonome (WebHID)** pour lire, sauvegarder et cloner des badges
NFC / RFID avec les lecteurs USB chinois de la famille **« wCopy / nsccn »**
(VID `0416` / `2518`), sans rien installer et **sans aucune connexion réseau**.

C'est une alternative libre à l'application d'origine (`nfcPro_x64.exe`), qui elle
envoie le contenu des cartes à des serveurs distants. Ici, tout reste sur ta machine.

> ⚠️ **Usage légal uniquement.** À n'utiliser que sur **tes propres** cartes et
> badges, ou avec l'autorisation explicite du propriétaire. Outil destiné à
> l'apprentissage, la sauvegarde et la récupération de tes propres accès.

---

## Fonctionnalités

- **Détection de carte** : UID, ATQA, SAK, type (MIFARE Classic, NTAG, Ultralight…).
- **MIFARE Classic** : lecture complète avec **dictionnaire de ~2490 clés** intégré
  (issu de *extended-std.keys*), chargement de dictionnaires supplémentaires,
  export `.dump`, export des clés, écriture de blocs.
- **Clonage sur carte magique** : écriture du bloc 0 / UID et copie intégrale d'un
  dump, via le **backdoor Gen1a** (commandes `40/43`, sans authentification) ou
  l'écriture directe **Gen2/CUID**.
- **Comparaison de deux dumps**, avec surlignage des octets qui diffèrent.
- **NTAG / Ultralight** : lecture et écriture de pages.
- **125 kHz** : lecture EM4100 / HID Prox.
- **Console** : envoi de commandes brutes et journal des échanges.
- **Moteur Crypto1** (`crypto1.js`) : portage propre de *crapto1* + récupération de
  clés *nested* (attaque hors-ligne, en cours d'intégration dans l'UI).

## Matériel requis

- Un lecteur USB de la famille **wCopy / nsccn** — VID:PID `0416:B030`, `0416:B031`,
  `2518:6022` ou `2518:6018`.
- Un navigateur basé sur **Chromium** (Chrome, Edge, Brave, Opera). WebHID n'est
  pas disponible sur Firefox ni Safari.
- Pour **cloner** : des cartes « magiques » à UID réinscriptible (MIFARE 1K
  **Gen1a** ou **Gen2/CUID**) pour le 13,56 MHz, ou **T5577** pour le 125 kHz.

## Utilisation

1. Ouvre **`nfc-tool.html`** dans Chrome/Edge/Brave.
2. Clique **« Connecter le lecteur »** et choisis le périphérique.
3. Pose une carte, puis utilise les onglets.

Un guide illustré pas-à-pas est fourni : **`GUIDE.html`**.

## Fichiers

| Fichier | Rôle |
|---|---|
| `nfc-tool.html` | L'application (à ouvrir dans le navigateur). |
| `crypto1.js` | Moteur Crypto1 + récupération de clés (nested). |
| `keys-extended.js` / `extended-std.keys` | Dictionnaire de clés chargé par défaut. |
| `GUIDE.html` + `guide-img/` | Guide d'utilisation illustré. |
| `PROTOCOLE-lecteur.md` | Documentation technique du protocole du lecteur (rétro-ingénierie). |

## Comment ça marche

Le lecteur est un périphérique USB-HID qui encapsule un contrôleur de type PN532.
Le protocole (trames, commandes) a été reconstitué par rétro-ingénierie —
voir [`PROTOCOLE-lecteur.md`](PROTOCOLE-lecteur.md). L'application parle au lecteur
directement via l'API **WebHID** du navigateur ; il n'y a **ni serveur, ni
télémétrie, ni dépendance en ligne**.

## Crédits & licence

- Dictionnaire de clés : **[MIFARE Classic Tool](https://github.com/ikarus23/MifareClassicTool)**
  (*extended-std.keys*), sous licence GPLv3.
- `crypto1.js` : réimplémentation propre de l'algorithme public **crapto1**.

En conséquence, ce dépôt est distribué sous **GPLv3**. Voir le fichier `LICENSE`.

## Avertissement

Projet personnel, fourni « tel quel », sans garantie. Le clonage de badges peut
être réglementé ; respecte la loi et n'agis que sur ce qui t'appartient.

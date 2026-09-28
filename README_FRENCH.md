# Check-Network

**Contrôle de la santé et de la sécurité réseau de Windows 10 / 11, en lecture seule.**
Un lancement, un rapport dans la console, un rapport HTML : ma connexion est-elle saine, mon DNS fait-il ce que je crois, et quelque chose sur ma machine expose-t-il ou laisse-t-il fuiter plus que prévu ?

🇬🇧 [English version → README.md](README.md)

---

## Sommaire

- [Pourquoi ce script est utile](#pourquoi-ce-script-est-utile)
- [Captures d'écran](#captures-décran)
- [Ce qu'il fait (et ne fait pas)](#ce-quil-fait-et-ne-fait-pas)
- [Prérequis](#prérequis)
- [Premier lancement](#premier-lancement-pas-à-pas)
- [Raccourci bureau](#raccourci-bureau)
- [Paramètres](#paramètres)
- [Lire l'affichage de la console](#lire-laffichage-de-la-console)
- [Ce que vérifie chaque section](#ce-que-vérifie-chaque-section)
- [Scores](#scores)
- [Rapports](#rapports)
- [Intégrations optionnelles (NextDNS, Block-Telemetry)](#intégrations-optionnelles-nextdns-block-telemetry)
- [Confidentialité](#confidentialité)
- [Dépannage](#dépannage)

---

## Pourquoi ce script est utile

Windows répartit l'information réseau à de nombreux endroits : Paramètres, `ipconfig`, `netstat`, la console du pare-feu, le fichier hosts, le gestionnaire de certificats, `netsh wlan`… et aucun ne dit si l'**ensemble** est correct.

Check-Network exécute des dizaines de vérifications en une seule passe et transforme les données brutes en un **statut par ligne** (OK / WARNING / ERROR / INFO) et **trois scores sur 100**. Il permet de :

- **Diagnostiquer une connexion lente ou instable** : latence vers la box, perte de paquets, débit réel en download/upload, vitesse de liaison, taux d'erreurs de l'interface, signal Wi-Fi.
- **Vérifier la configuration DNS** : quels serveurs DNS sont réellement utilisés, si le DNS chiffré (DoH/DoT) est actif, s'il existe une fuite DNS ou une application qui contourne votre résolveur.
- **Repérer l'exposition côté sécurité** : ports en écoute accessibles depuis le réseau, processus à l'écoute sur `0.0.0.0`, SMBv1, partages ouverts, partage de connexion (ICS), proxys, NetBIOS, certificats racines inhabituels, adresses MAC en double dans le cache ARP.
- **Suivre l'évolution** : chaque lancement est comparé au rapport JSON précédent et une courbe du score est tracée dans le rapport HTML.

Il est pensé pour être **compris par des non-experts** : chaque ligne de la console indique ce qui a été vérifié, la valeur trouvée et si tout va bien.

## Captures d'écran

<p align="center">
  <img src="https://raw.githubusercontent.com/NephVx2/Check-Network/main/screenshots/01-banner-sysinfo.png" width="49%">
  <img src="https://raw.githubusercontent.com/NephVx2/Check-Network/main/screenshots/04-banner-html.png" width="49%">
</p>

Davantage dans [`screenshots/`](https://github.com/NephVx2/Check-Network/tree/main/screenshots) : sortie console section par section, et le rapport HTML complet.

---

## Ce qu'il fait (et ne fait pas)

**Il inspecte uniquement.** Il ne modifie jamais votre DNS, votre pare-feu, votre fichier hosts, votre proxy ni vos paramètres réseau.

Ce qu'il écrit ou envoie :

| Action | Détails |
|---|---|
| Écrit des rapports | Un fichier CSV, un HTML et un JSON dans `Desktop\Maintenance_Reports\Check Network` |
| Supprime d'anciens rapports | Uniquement les fichiers `Network_Report_*` (et les anciens `Rapport_Reseau_*`) de ce dossier, de plus de 60 jours (`-PurgeDays`, `0` désactive) |
| Trafic réseau | Test de débit vers `speed.cloudflare.com` (télécharge 5 Mo, envoie 2 Mo de données factices) ; test de portail captif vers `msftconnecttest.com` ; sondes DNS/TCP vers des résolveurs publics et votre routeur |
| Paramètres de session | `Set-ExecutionPolicy Bypass` pour la session PowerShell en cours uniquement |
| Notification | Une notification Windows avec le score en fin d'exécution |

Rien n'est envoyé nulle part. Les mots de passe Wi-Fi ne sont **jamais** lus (seule la présence d'une clé est vérifiée).

## Prérequis

- Windows 10 ou Windows 11.
- PowerShell 5.1 (intégré à Windows) ou PowerShell 7+.
- Droits administrateur (le script s'auto-élève via une invite UAC s'il est lancé depuis une session non élevée ; la relance élevée utilise Windows PowerShell 5.1).
- L'accès Internet n'est nécessaire que pour le test de débit et la détection de portail captif (le test de débit peut être sauté avec `-SkipSpeedTest`) ; toutes les autres vérifications fonctionnent hors ligne.
- Les sections Wi-Fi n'apparaissent que si une connexion Wi-Fi est détectée.
- Fonctionne sur Windows en anglais comme en français : l'affichage du script est en anglais, et la sortie de `netsh wlan` qu'il lit est analysée dans les deux langues.
- Optionnel : le client de bureau NextDNS et le bloc Block-Telemetry dans le fichier hosts. Sans eux, les lignes correspondantes sont purement informatives (voir [Intégrations optionnelles](#intégrations-optionnelles-nextdns-block-telemetry)).
- Si le script est signé numériquement (recommandé en environnement `-ExecutionPolicy AllSigned`/`RemoteSigned`) : le certificat de signature doit être approuvé sur la machine cible.

---

## Premier lancement (pas à pas)

1. Copier `Check-Network.ps1` sur la machine cible.

2. Ouvrir PowerShell en tant qu'administrateur (recommandé : le script s'auto-élève de toute façon via une invite UAC, mais l'exécuter dans une fenêtre déjà élevée garde l'affichage dans votre fenêtre, au lieu d'une nouvelle fenêtre qui se ferme à la fin de `-SelfTest`).

   Puis se placer dans le dossier qui contient le script (adapter le chemin ; garder les guillemets s'il contient des espaces) :

   ```powershell
   cd "$HOME\Downloads"
   ```

3. **Débloquer le script** s'il a été téléchargé depuis Internet. Windows marque les fichiers téléchargés, et la politique d'exécution de PowerShell (`RemoteSigned`, par exemple) refuse de lancer un script marqué. Depuis le dossier du script :

   ```powershell
   Unblock-File .\Check-Network.ps1
   ```

   Si PowerShell indique plutôt que l'exécution de scripts est désactivée sur ce système (la politique par défaut de Windows est `Restricted`), autoriser d'abord les scripts pour le compte courant (la modification ne s'applique qu'à ce compte, pas à toute la machine) :

   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```

   Toujours bloqué ? Voir le [guide pas à pas](https://github.com/NephVx2/Script-blocked-Look-at-this/blob/main/README_POWERSHELL_FRENCH.md).

4. Lancer d'abord le self-test : aucune analyse réseau, aucun rapport écrit, aucune modification système :

   ```powershell
   .\Check-Network.ps1 -SelfTest
   ```

   Exécute 14 assertions internes (libellés des états de score, calcul de la perte de paquets, logique du filtre `-Category`, et plus) et affiche `Result: 14 / 14 assertions passed` quand tout va bien.

5. Lancer l'analyse complète :

   ```powershell
   .\Check-Network.ps1
   ```

   Elle prend un moment selon la machine et la connexion (le test de débit est l'étape la plus visible). Suivre la console : les sections numérotées s'affichent une fois l'analyse terminée, une ligne par vérification avec une icône `✓` / `!` / `✗` / `·`.

6. À la fin, la console affiche un cadre **ANALYSIS COMPLETE** avec les trois scores, suivi de jusqu'à 5 constats `ERROR` et 5 `WARNING` pour une lecture immédiate sans ouvrir le rapport HTML.

7. Répondre `Y` (Yes) pour ouvrir le rapport HTML généré (la question est ignorée avec `-Silent`). Commencer par les alertes en haut, puis utiliser la barre de recherche et le filtre par statut pour aller vers une vérification précise.

8. Aux **deuxième lancement et suivants**, la section **Comparison** liste ce qui a changé depuis le rapport JSON précédent, et le rapport HTML trace l'évolution du score global.

9. Si une ligne est peu claire ou inattendue (serveur DNS inconnu, certificat racine inhabituel, port exposé), ne pas se fier uniquement au libellé : vérifier auprès de votre routeur, de votre fournisseur d'accès ou de l'éditeur du logiciel avant de modifier quoi que ce soit. Le script inspecte seulement, il ne corrige rien.

---

## Raccourci bureau

Pour un lancement en un clic, créez un raccourci avec l'une de ces cibles :

| Shell | Cible |
|---|---|
| Windows PowerShell 5.1 (inclus) | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Chemin\Vers\Check-Network.ps1"` |
| PowerShell 7 | `pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Chemin\Vers\Check-Network.ps1"` |

| Option | Signification |
|---|---|
| `-NoProfile` | Démarre sans charger votre profil PowerShell (plus rapide, comportement prévisible) |
| `-ExecutionPolicy Bypass` | Autorise l'exécution de ce script quelle que soit la stratégie de la machine, pour cette session uniquement |
| `-File "…"` | Le script à exécuter. Gardez les guillemets si le chemin contient des espaces |

Le script demande lui-même l'élévation ; inutile de cocher « Exécuter en tant qu'administrateur » dans le raccourci.

## Paramètres

| Paramètre | Description |
|---|---|
| `-Silent` | Aucun affichage console : génère les fichiers et affiche seulement la notification. Utile pour une tâche planifiée |
| `-SelfTest` | Valide les fonctions clés du script (scores, filtre de catégories, calcul de perte de paquets…) puis quitte, sans analyser le réseau |
| `-Category <liste>` | Limite les sections optionnelles / lentes. Valeurs : `Speed`, `RootCerts`, `WiFi`, `Comparison`. Par défaut : `All`. Les contrôles de base s'exécutent toujours |
| `-SkipSpeedTest` | Saute le test de download/upload (pratique sur connexion limitée ou en tâche planifiée) |
| `-PurgeDays <n>` | Supprime les rapports de plus de *n* jours. Par défaut `60`, `0` désactive la purge |

Exemples :

```powershell
.\Check-Network.ps1                          # exécution complète
.\Check-Network.ps1 -SkipSpeedTest           # sans test de débit
.\Check-Network.ps1 -Category Speed,WiFi     # contrôles de base + débit + Wi-Fi uniquement
.\Check-Network.ps1 -Silent -PurgeDays 0     # tâche planifiée, conserve tous les rapports
.\Check-Network.ps1 -SelfTest                # valide le script lui-même
```

## Lire l'affichage de la console

Le rapport est découpé en sections numérotées et encadrées. Chaque vérification tient sur une ligne :

```
   ✓  Gateway         │ Latency to 192.168.1.1 : Avg 3.1 ms | Min 2 ms | Max 5 ms
   !  DNS             │ Wi-Fi - DNS IPv4 : 80.10.246.2
   ✗  Speed           │ Download (Cloudflare) : 6 Mbps (4.8 MB in 6.68s)
   ·  NextDNS         │ Installation : Not detected
```

Colonnes : **icône** · **catégorie** · `│` · **vérification** `:` **valeur**. Les valeurs longues passent à la ligne suivante, alignées sous le `│`.

Les libellés de la console sont en anglais (ils sont identiques sur une machine Windows française ou anglaise).

| Icône | Couleur | Signification |
|---|---|---|
| `✓` | Vert | **OK** : rien à faire |
| `!` | Jaune | **WARNING** : à regarder, pas forcément un problème (−5 points sur le score concerné) |
| `✗` | Rouge | **ERROR** : un vrai problème ou une valeur clairement risquée (−15 points) |
| `·` | Cyan | **INFO** : information, sans effet sur le score |

À la fin, un cadre vert **ANALYSIS COMPLETE** affiche les trois scores sous forme de jauges (`█████░░░`), le nombre total de vérifications avec les compteurs OK / WARN / ERROR, et les cinq premières erreurs et alertes pour agir sans ouvrir le rapport HTML. Les chemins des fichiers générés suivent, précédés de `»`.

## Ce que vérifie chaque section

### 1. Système et connexion
- **System / Connection / Interfaces** : version de Windows, type de connexion (Ethernet, Wi-Fi, VPN), carte principale et état de chaque carte réseau.
- **IP / Gateway** : adresses IPv4 / IPv6, passerelle par défaut, serveurs DNS par interface. Un serveur DNS public absent de la liste des résolveurs connus déclenche une alerte : ce peut être celui de votre fournisseur d'accès ou un serveur inattendu.
- **Latence de la passerelle** : 4 sondes vers votre routeur. Moyenne ≤ 25 ms OK, ≤ 50 ms alerte, au-delà erreur. La **perte de paquets** est aussi indiquée : 0 % OK, ≤ 25 % alerte, au-delà erreur. Une liaison Wi-Fi peut avoir une bonne latence moyenne tout en perdant des paquets.
- **Speed** : téléchargement de 5 Mo et envoi de 2 Mo via Cloudflare. Download ≥ 50 Mbps OK, ≥ 10 Mbps alerte ; upload ≥ 10 Mbps OK, ≥ 2 Mbps alerte. Un fichier de 5 Mo sous-estime légèrement les liaisons très rapides.
- **Performance / Network Stats** : vitesse de liaison négociée (≥ 100 Mbps OK) et taux d'erreurs de la carte principale (0 % OK, < 0,1 % alerte).
- **Routing** : route(s) par défaut. Plusieurs routes par défaut (par exemple Wi-Fi et Ethernet en même temps) déclenchent une alerte.
- **IPv6** : IPv6 activé ou non, et sur combien d'interfaces connectées.

### 2. Internet et portail captif
- **Internet** : résolution DNS de domaines de test, joignabilité TCP/UDP de serveurs DNS publics, connectivité générale.
- **Network** : détection de portail captif (Wi-Fi d'hôtel, de café ou d'aéroport qui vous redirige vers une page de connexion).

### 3. DNS, NextDNS et fuites
- **DNS** : temps de résolution de domaines courants, et vérification que les réponses ne sont pas détournées.
- **NextDNS / DoH Windows / DNS Leak / Bypass DNS / IPv6 Leak** : voir [Intégrations optionnelles](#intégrations-optionnelles-nextdns-block-telemetry). Sans NextDNS, ces lignes sont simplement `INFO`.
- **DNS Cache** : classe le contenu actuel du cache DNS de Windows : infrastructure légitime, télémétrie connue, domaines bloqués (résolus vers `0.0.0.0` / `127.0.0.1`), noms suspects (domaines générés algorithmiquement, extensions dangereuses, motifs de malware).
- **Hosts File** : nombre d'entrées redirigées vers rien dans votre fichier hosts, et combien ont été vues récemment dans le cache DNS (le cache ne montre que les domaines interrogés depuis le dernier vidage, une couverture inférieure à 100 % est donc normale).

### 4. Sécurité réseau
- **Firewall / Network Profile** : les trois profils du pare-feu (Domaine / Privé / Public) doivent être actifs ; catégorie du réseau actuel (Public est la plus restrictive).
- **TCP Ports / UDP Ports** : ports en écoute. Les services sensibles (FTP, Telnet, SMB, RDP…) ou les ports à l'écoute sur toutes les interfaces (`0.0.0.0`) sont signalés, avec le processus concerné.
- **Processes** : processus non système exposés sur `0.0.0.0`.
- **Connections / Outbound** : connexions TCP établies, ports distants suspects et connexions sortantes de chaque processus.
- **SMB** : partages non par défaut et activation ou non du protocole obsolète et vulnérable SMBv1.
- **Proxy** : paramètres de proxy WinINET et WinHTTP (un proxy que vous n'avez pas configuré peut intercepter le trafic).
- **NetBIOS** : état de NetBIOS sur TCP/IP (un risque sur les réseaux publics).
- **ARP** : adresses MAC en double dans le cache ARP, signe classique d'usurpation ARP.
- **Certificates** : certificats racines hors de la liste habituelle de confiance Microsoft (un certificat racine frauduleux permet d'intercepter le HTTPS ; sur un PC d'entreprise, certains sont normaux).
- **ICS** : partage de connexion Internet de Windows, qui transforme votre PC en routeur.

### 5. Wi-Fi et historique
- **Wi-Fi** : SSID, authentification (WPA3 / WPA2 OK, WPA alerte, WEP / ouvert erreur), signal (≥ 70 % OK, ≥ 40 % alerte), standard radio et canal.
- **Wi-Fi History** : profils Wi-Fi enregistrés et leur type d'authentification ; les réseaux faibles ou ouverts auxquels vous vous êtes déjà connecté sont signalés.

### 6. Comparaison et évolution
- **Comparison** : différences avec le rapport JSON précédent (éléments passés de OK à WARNING / ERROR, ou inversement).
- **Maintenance** : nombre d'anciens rapports purgés.

## Scores

Chaque ligne WARNING retire **5 points** et chaque ERROR **15 points** au score auquel elle appartient. Il y a trois scores, tous à 100 au départ :

| Score | Couvre |
|---|---|
| **Connectivity** | Passerelle, débit, interfaces, routage, signal Wi-Fi, IPv6 |
| **Security** | Pare-feu, ports, processus, SMB, proxy, certificats, ARP, sécurité Wi-Fi |
| **DNS** | Serveurs DNS, résolution, NextDNS, fuites, cache DNS, fichier hosts |

Le **score global** est la moyenne des trois. États affichés dans la console : **EXCELLENT** ≥ 90 · **GOOD** ≥ 75 · **FAIR** ≥ 50 · **CRITICAL** en dessous de 50. (Couleurs du rapport HTML : vert ≥ 90, orange ≥ 60, rouge en dessous.)

## Rapports

Les fichiers sont enregistrés dans `%USERPROFILE%\Desktop\Maintenance_Reports\Check Network` :

| Fichier | Contenu |
|---|---|
| `Network_Report_<aaaa-MM-jj_HH-mm>.html` | Rapport à thème sombre : anneaux de score, évolution du score sur les lancements précédents, alertes, sections repliables, recherche et filtre par statut en direct |
| `Network_Report_<aaaa-MM-jj_HH-mm>.csv` | Tous les résultats, une ligne par vérification |
| `Network_Report_<aaaa-MM-jj_HH-mm>.json` | Mêmes données pour les outils, et base de comparaison du lancement suivant |

## Intégrations optionnelles (NextDNS, Block-Telemetry)

Aucune n'est requise. Si vous ne les utilisez pas, les lignes correspondantes affichent `INFO` et **ne baissent pas votre score**.

- **NextDNS** (client de bureau) : lorsqu'il est détecté, le script vérifie le service, le processus, le mode de transport (DoH / DoT / classique), la latence vers les serveurs NextDNS, si le DNS de Windows passe réellement par lui, et recherche les fuites DNS (requêtes sur le port 53 qui le contournent, y compris en IPv6) ainsi que les applications utilisant un DNS codé en dur.
- **Block-Telemetry** (script compagnon) : lorsque son bloc est trouvé dans le fichier hosts, Check-Network compte les domaines qu'il contient et vérifie l'âge du fichier (≤ 120 jours OK, ≤ 240 alerte, au-delà erreur). Sans ce bloc, l'âge du fichier est affiché à titre d'information uniquement.

## Confidentialité

Le rapport contient des informations sur **votre machine** : noms de cartes, adresses IP, noms de réseaux Wi-Fi, noms de processus et ports. Il est généré localement et n'est envoyé nulle part. Avant de partager une capture d'écran ou un rapport publiquement, masquez ces informations.

## Dépannage

<details>
<summary>La fenêtre s'ouvre puis se ferme aussitôt</summary>

Lancez le script depuis une fenêtre PowerShell déjà ouverte (`.\Check-Network.ps1`) pour voir l'éventuel message d'erreur, et vérifiez que la demande UAC a bien été acceptée.
</details>

<details>
<summary>Le débit affiché est très faible</summary>

Le test télécharge 5 Mo : il mesure aussi le démarrage de la connexion et peut sous-estimer une liaison très rapide. Comparez avec un test de débit dans le navigateur ; si l'écart est important, relancez le script sans autre usage de la connexion.
</details>

<details>
<summary>Alerte sur un serveur DNS public</summary>

Le script ne connaît que les résolveurs publics les plus courants. Si l'adresse est celle de votre fournisseur d'accès ou d'un serveur choisi volontairement, l'alerte est simplement informative.
</details>

<details>
<summary>Plusieurs certificats racines signalés</summary>

Les entreprises, les écoles et certains logiciels de sécurité installent leurs propres certificats racines. Relisez la liste : ce n'est un problème que si vous ne reconnaissez pas l'émetteur.
</details>

<details>
<summary>Les symboles s'affichent en carrés ou les cadres sont décalés</summary>

Utilisez Windows Terminal, ou une police de console qui gère les caractères de cadre (Consolas, Cascadia Mono).
</details>


# Transparency-AI - Backend

Ce dépôt contient le code source du backend de Transparency-AI. Ce backend, développé en Go, implémente une API RESTful avec les fonctionnalités de gestion des utilisateurs (CRUD). Il utilise le framework **Echo** pour la gestion des requêtes HTTP, et l'authentification sécurisée via des cookies HTTP-only.

Ce backend est conçu pour être simple à installer et exécuter, notamment grâce à **Docker**. Les fonctionnalités clés incluent un CRUD utilisateur prêt à l'emploi et une documentation automatique des routes grâce à **GoDoc**.

---

## Résumé de la feature

### Utilité
Poser les bases d'un backend en Go avec un CRUD utilisateur, ce qui constitue un point de départ solide pour tout projet backend.

### Contexte
Ceci est une fonctionnalité de base essentielle pour gérer les utilisateurs dans toute application moderne.

### Objectif
Avoir un backend fonctionnel et prêt à être livré, avec les éléments suivants :
- Une API RESTful construite avec **Echo**.
- Une gestion sécurisée des sessions via cookies HTTP-only.
- Documentation automatique des routes grâce à **GoDoc**.

---

## Table des matières

- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
- [Lancer l'application](#lancer-lapplication)
- [Tests](#tests)
- [Contact](#contact)

---

## Prérequis

Pour exécuter ce projet, vous aurez besoin de :

- **Docker** et **Docker Compose** (recommandé).
- Si Docker n'est pas utilisé : **Go 1.20 ou plus**.

---

## Installation

### Cloner le repo

1. Ajouter votre clé SSH .pub dans la section "User Settings/SSH Keys"

2. Clonez ce dépôt en SSH :
   ```bash
   git clone git@gitlab.transparency-ai.fr:transparency/backend.git
   cd backend
   ```

### Avec Docker (recommandé)

1. Construisez et démarrez l'application avec Docker Compose :
   ```bash
   docker-compose up --build
   ```

3. Une fois démarré, le backend est accessible à :
   ```
   http://localhost:8080
   ```

### Sans Docker (développement local)

1. Installez les dépendances Go :
   ```bash
   go mod tidy
   ```

3. Lancez l'application :
   ```bash
   go run main.go
   ```

---

## Configuration

Les variables de configuration sont gérées via un fichier `.env` à la racine du projet.

> **Note :** Assurez-vous de définir un `JWT_SECRET` fort pour sécuriser les tokens d'authentification.

---

## Lancer l'application

### Avec Docker Compose

Pour démarrer l'application avec Docker Compose, utilisez :
```bash
docker-compose up --build
```

Les logs du serveur seront affichés dans la console. Pour arrêter le serveur :
```bash
docker-compose down
```

### En local (développement)

Si vous n’utilisez pas Docker, vous pouvez lancer l'application localement avec :
```bash
go run main.go
```

L'API sera accessible à `http://localhost:8080`.

---

### Description des dossiers

- **routes/** : Contient les définitions des endpoints HTTP.
- **controllers/** : Contient la logique métier associée à chaque route.
- **models/** : Définit les structures des données (par exemple, utilisateurs).
- **middleware/** : Contient les middlewares pour la gestion des cookies et de la sécurité.

---

## Tests

Les tests sont écrits en Go et peuvent être exécutés via la commande suivante :

```bash
go test ./...
```

Si vous utilisez Docker, lancez les tests dans un conteneur isolé :
```bash
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

---

## Critères de réussite

Pour considérer le backend comme terminé, les critères suivants doivent être remplis :
- Le projet compile sans erreur.
- L'API fonctionne avec le framework **Echo**.
- L'authentification via cookies sécurisés est en place.
- Les routes CRUD sont documentées avec **GoDoc**.

---

## Contact

Pour toute question, suggestion ou problème, contactez-nous à [contact@transparency-ai.com](mailto:contact@transparency-ai.com).

---

Merci de contribuer à **Transparency-AI - Backend** !

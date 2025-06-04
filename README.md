## Firebase-WooCommerce Integration

### ✨ Plugin per sincronizzazione utenti tra WooCommerce e Firebase.

---

### 🔁 Flusso

#### Caso A – Registrazione via app (Firebase)

* L'utente si registra nell'app (tramite Firebase Auth)
* Il backend Express chiama:

  ```
  POST /wp-json/firebase/v1/create-user
  ```
* WordPress crea l'utente WooCommerce corrispondente, con ruolo `customer`

#### Caso B – Registrazione via WooCommerce

* L’utente si registra tramite `/my-account` o in fase di checkout
* WooCommerce intercetta la password da `$_POST`
* Alla creazione dell’utente (`user_register`), WordPress chiama il backend Express per creare l’utente su Firebase

---

### 🔐 Sicurezza

* Tutte le chiamate server-to-server sono protette via header:

  ```
  X-WP-Secret: <shared secret>
  ```
* Nel file `wp-config.php`, aggiungi:

  ```php
  define('FIREBASE_SYNC_SECRET', 'la-tua-chiave-super-segreta');
  define('FIREBASE_SYNC_ENDPOINT', 'https://tuo-backend.it/api/firebase-sync');
  ```

---

### ⚙️ Setup

1. Installa il plugin all’interno di WordPress (come plugin ZIP oppure via FTP)
2. Aggiungi le costanti nel `wp-config.php` come indicato sopra
3. Il tuo backend Express deve:

    * Esporre `/api/firebase-sync` (protetto da `X-WP-Secret`)
    * Chiamare `/wp-json/firebase/v1/create-user` ogni volta che registra un nuovo utente Firebase

---

### 🧪 Debug

* Il plugin logga tutto solo se `WP_DEBUG === true`
* Tutti i `error_log()` sono condizionati, quindi in produzione non scrive nulla

---

### ✅ Stato attuale

* [x] Registrazione Woo → Firebase
* [x] Registrazione Firebase → Woo
* [x] Sicurezza server-to-server
* [x] Logging controllato da `WP_DEBUG`
* [x] Pulizia automatica dei dati sensibili (password via `transient` TTL)

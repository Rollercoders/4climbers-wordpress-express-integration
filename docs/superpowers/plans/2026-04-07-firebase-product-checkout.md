# Firebase Product Checkout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Aggiungere supporto al parametro `product_id` nel flusso Firebase login, così che dopo il login il prodotto venga aggiunto al carrello (svuotato prima) e l'utente venga reindirizzato al checkout.

**Architecture:** Modifica inline di `wc_handle_firebase_login` in `4climbers-wordpress-express-integration.php`. Si aggiorna anche la condizione di guard iniziale per accettare `product_id` come alternativa a `page`. La logica di redirect viene estesa con un branch dedicato al caso `product_id`.

**Tech Stack:** PHP, WordPress, WooCommerce (`wc_get_product`, `WC()->cart`), Firebase (kreait/firebase-tokens).

---

## File Map

- **Modify:** `4climbers-wordpress-express-integration.php`
  - Funzione `wc_handle_firebase_login` (righe 479-532): guard iniziale + logica redirect

---

### Task 1: Aggiornare la guard iniziale per accettare `product_id`

**Files:**
- Modify: `4climbers-wordpress-express-integration.php:481`

La condizione attuale richiede obbligatoriamente `page`. Con il nuovo parametro `product_id`, `page` non è più obbligatorio: è sufficiente avere `firebase_login` + `token` + (almeno uno tra `page` o `product_id`).

- [ ] **Step 1: Modificare la condizione di guard in `wc_handle_firebase_login`**

Sostituire righe 481-483:

```php
    if (!isset($_GET['firebase_login']) || !isset($_GET['token']) || !isset($_GET['page'])) {
        return;
    }
```

Con:

```php
    if (!isset($_GET['firebase_login']) || !isset($_GET['token'])) {
        return;
    }

    if (!isset($_GET['page']) && !isset($_GET['product_id'])) {
        return;
    }
```

- [ ] **Step 2: Verificare manualmente che il comportamento esistente non sia rotto**

Aprire il file e controllare che le righe 479-484 corrispondano esattamente al codice sopra.

- [ ] **Step 3: Commit**

```bash
git add 4climbers-wordpress-express-integration.php
git commit -m "fix: accept product_id as alternative to page in firebase login guard"
```

---

### Task 2: Aggiungere la logica carrello e redirect al checkout

**Files:**
- Modify: `4climbers-wordpress-express-integration.php:513-527`

Dopo il set della sessione WordPress (riga 511), aggiungere il branch `product_id` prima della logica `page` esistente.

- [ ] **Step 1: Sostituire il blocco redirect (righe 513-527)**

Sostituire:

```php
        $page = $_GET['page'];

        // Forward ios_show_cookie_banner parameter if present
        $queryString = '';
        if (isset($_GET['ios_show_cookie_banner'])) {
            $queryString = '?ios_show_cookie_banner=' . sanitize_text_field($_GET['ios_show_cookie_banner']);
        }

        if ($page !== 'checkout') {
            wp_redirect(home_url("/$page" . $queryString));
            exit;
        }

        wp_redirect(home_url('/premium' . $queryString));
        exit;
```

Con:

```php
        // Forward ios_show_cookie_banner parameter if present
        $queryString = '';
        if (isset($_GET['ios_show_cookie_banner'])) {
            $queryString = '?ios_show_cookie_banner=' . sanitize_text_field($_GET['ios_show_cookie_banner']);
        }

        if (isset($_GET['product_id'])) {
            $product_id = absint($_GET['product_id']);

            if ($product_id <= 0) {
                wp_die('ID prodotto non valido');
            }

            $product = wc_get_product($product_id);

            if (!$product || !$product->is_purchasable() || !$product->is_in_stock()) {
                debug_log("wc_handle_firebase_login", "Prodotto non valido: $product_id");
                wp_die('Prodotto non trovato o non acquistabile');
            }

            WC()->cart->empty_cart();
            $result = WC()->cart->add_to_cart($product_id);

            if (!$result) {
                debug_log("wc_handle_firebase_login", "add_to_cart fallito per product_id: $product_id");
                wp_die('Impossibile aggiungere il prodotto al carrello');
            }

            wp_redirect(home_url('/checkout' . $queryString));
            exit;
        }

        $page = $_GET['page'];

        if ($page !== 'checkout') {
            wp_redirect(home_url("/$page" . $queryString));
            exit;
        }

        wp_redirect(home_url('/premium' . $queryString));
        exit;
```

- [ ] **Step 2: Verificare il file risultante**

Aprire `4climbers-wordpress-express-integration.php` e controllare che:
1. Il branch `product_id` appaia prima del branch `page`
2. La variabile `$queryString` sia definita prima del branch `product_id`
3. Il branch `page` esistente sia rimasto invariato sotto

- [ ] **Step 3: Commit**

```bash
git add 4climbers-wordpress-express-integration.php
git commit -m "feat: add product_id support in firebase login — empty cart, add product, redirect to checkout"
```

---

## Self-Review checklist

- [x] Guard accetta `product_id` senza `page` ✓
- [x] `$queryString` calcolato prima di entrambi i branch ✓
- [x] Carrello svuotato prima di `add_to_cart` ✓
- [x] Tutti i casi di errore coperti con `wp_die` + `debug_log` ✓
- [x] Comportamento `page` esistente invariato ✓
- [x] `ios_show_cookie_banner` propagato anche al redirect checkout ✓

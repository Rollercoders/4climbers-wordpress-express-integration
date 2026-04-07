# Design: Firebase Login con Product Checkout

**Data:** 2026-04-07  
**File coinvolto:** `4climbers-wordpress-express-integration.php`

## Contesto

Il flusso attuale permette di autenticare un utente tramite Firebase idToken e poi reindirizzarlo a una pagina WordPress. Il parametro `page=checkout` reindirizzava genericamente a `/premium`.

Il cliente vuole ora poter passare l'ID di un prodotto specifico: dopo il login, quel prodotto viene aggiunto al carrello e l'utente viene mandato direttamente al checkout.

## Nuovo URL

```
<base_url>?firebase_login=1&token=$idToken&product_id=123
```

Il parametro `page` rimane supportato per i redirect generici esistenti. `product_id` è il nuovo parametro dedicato.

## Approccio scelto

Modifica inline di `wc_handle_firebase_login` — aggiunta della logica carrello direttamente nella funzione esistente, dopo il set della sessione WordPress.

## Flusso

```
URL: ?firebase_login=1&token=eyJ...&product_id=123
        ↓
  Valida idToken Firebase
        ↓
  Cerca utente per email in WordPress
        ↓
  Crea sessione + cookie persistente
        ↓
  product_id presente?
    ├── NO  → comportamento attuale (redirect a /$page o /premium)
    └── SI  →
          Valida product_id (intero positivo)
                ↓
          wc_get_product() → purchasable + in stock?
                ↓
          WC()->cart->empty_cart()
                ↓
          WC()->cart->add_to_cart($product_id)
                ↓
          Redirect → /checkout
```

## Dettagli implementativi

### Detection

In `wc_maybe_hook_firebase_login`: nessun cambiamento, `product_id` non è richiesto per hookare.

In `wc_handle_firebase_login`, dopo il login:
- Se `product_id` è presente → gestisci checkout con prodotto
- Altrimenti → comportamento attuale invariato

### Logica carrello

```php
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
```

### Propagazione `ios_show_cookie_banner`

Il parametro viene propagato anche nel redirect al checkout, coerentemente con il comportamento esistente.

## Gestione errori

| Caso | Comportamento |
|------|---------------|
| `product_id` non numerico o <= 0 | `wp_die('ID prodotto non valido')` |
| Prodotto non trovato | `wp_die('Prodotto non trovato o non acquistabile')` + log |
| Prodotto non purchasable o fuori stock | `wp_die('Prodotto non trovato o non acquistabile')` + log |
| `add_to_cart()` ritorna `false` | `wp_die('Impossibile aggiungere il prodotto al carrello')` + log |

## Retrocompatibilità

- URL senza `product_id` → comportamento invariato
- `page=checkout` → continua a redirectare a `/premium`
- Tutti gli altri valori di `page` → redirect a `/$page`

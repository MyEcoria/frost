# frost-ed25519-blake2b wasm bindings

Bindings `wasm-pack` pour utiliser `frost-ed25519-blake2b` depuis TypeScript.

## Prérequis

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
npm login
```

## Build du package npm

Depuis `frost-ed25519-blake2b/bindings/node`:

```bash
wasm-pack build --release --target bundler --out-dir pkg
```

Si vous voulez publier sous scope npm (ex: `@myecoria/...`):

```bash
wasm-pack build --release --target bundler --scope myecoria --out-dir pkg
```

## API exposée

Toutes les données crypto sont échangées en bytes sérialisés (`Uint8Array`).

### `init() -> Promise<WebAssembly.Exports>`

Initialise le module WASM.  
À appeler une fois au démarrage avant les autres fonctions.

### `generate_with_dealer(max_signers, min_signers) -> DealerKeygenResult`

Génère une configuration FROST complète avec un dealer:

- une clé publique de groupe (`public_key_package`)
- des parts pour chaque participant (`share(i)`)

Paramètres:

- `max_signers`: nombre total de participants
- `min_signers`: seuil minimum de signatures

Utilisation typique: bootstrapping d'un groupe neuf.

### `key_package_from_secret_share(secret_share_bytes) -> Uint8Array`

Convertit une `SecretShare` sérialisée en `KeyPackage` sérialisé.

Utilisation typique: si vous stockez/transmettez `secret_share` et voulez recréer le `key_package` au moment de signer.

### `round1_commit(key_package_bytes) -> Round1CommitResult`

Calcule les éléments du round 1 pour un signataire:

- `identifier`
- `nonces` (secret, à conserver côté signataire)
- `commitments` (public, à partager avec l'agrégateur)

### `create_signing_package(commitment_list, message_bytes) -> Uint8Array`

Construit le `SigningPackage` (agrégateur) à partir:

- de la liste des commitments des signataires actifs
- du message à signer

Erreurs courantes:

- identifiant dupliqué dans `CommitmentList`

### `round2_sign(signing_package_bytes, nonces_bytes, key_package_bytes) -> Round2SignatureShareResult`

Produit une signature partielle (`signature_share`) pour un signataire donné, à partir:

- du `SigningPackage`
- de ses `nonces` round 1
- de son `key_package`

### `aggregate_signature(signing_package_bytes, signature_share_list, public_key_package_bytes) -> Uint8Array`

Agrège les signatures partielles pour produire la signature de groupe finale.

Erreurs courantes:

- identifiant dupliqué dans `SignatureShareList`
- nombre de parts insuffisant (moins que `min_signers`)
- parts invalides/incohérentes

### `verify_group_signature(public_key_package_bytes, message_bytes, signature_bytes) -> boolean`

Vérifie la signature finale contre la clé publique de groupe et le message.

- `true`: signature valide
- `false`: signature cryptographiquement invalide
- exception: problème de parsing/sérialisation

## Structures TS (générées par wasm-bindgen)

### `DealerKeygenResult`

- `public_key_package: Uint8Array`: clé publique de groupe sérialisée.
- `shares_len: number`: nombre de parts disponibles.
- `share(index: number): DealerShare`: récupère la part à l'index donné.

### `DealerShare`

- `identifier: Uint8Array`: identifiant du participant.
- `secret_share: Uint8Array`: part secrète sérialisée.
- `key_package: Uint8Array`: package de clé prêt pour la signature.

### `Round1CommitResult`

- `identifier: Uint8Array`: identifiant du signataire.
- `nonces: Uint8Array`: nonces round 1 (à garder secrets).
- `commitments: Uint8Array`: engagements publics round 1.

### `Round2SignatureShareResult`

- `identifier: Uint8Array`: identifiant du signataire.
- `signature_share: Uint8Array`: signature partielle round 2.

### `CommitmentList`

- `new CommitmentList()`
- `push(identifier, commitment)`: ajoute un commitment round 1.
- `len`: nombre d'entrées.
- `clear()`: vide la liste.

### `SignatureShareList`

- `new SignatureShareList()`
- `push(identifier, signature_share)`: ajoute une signature partielle.
- `len`: nombre d'entrées.
- `clear()`: vide la liste.

## Ordre d'utilisation recommandé

1. `await init()`
2. `generate_with_dealer(...)`
3. pour chaque signataire actif: `round1_commit(...)`
4. `create_signing_package(...)`
5. pour chaque signataire actif: `round2_sign(...)`
6. `aggregate_signature(...)`
7. `verify_group_signature(...)`

## Exemple TypeScript

```ts
import init, {
  CommitmentList,
  SignatureShareList,
  aggregate_signature,
  create_signing_package,
  generate_with_dealer,
  round1_commit,
  round2_sign,
  verify_group_signature,
} from "frost-ed25519-blake2b-wasm";

await init();

const message = new TextEncoder().encode("message to sign");
const dealer = generate_with_dealer(5, 3);

const commitmentList = new CommitmentList();
const round1Results = [];

for (let i = 0; i < 3; i += 1) {
  const share = dealer.share(i);
  const round1 = round1_commit(share.key_package);
  round1Results.push({ round1, keyPackage: share.key_package });
  commitmentList.push(round1.identifier, round1.commitments);
}

const signingPackage = create_signing_package(commitmentList, message);

const signatureShareList = new SignatureShareList();
for (const item of round1Results) {
  const round2 = round2_sign(signingPackage, item.round1.nonces, item.keyPackage);
  signatureShareList.push(round2.identifier, round2.signature_share);
}

const signature = aggregate_signature(
  signingPackage,
  signatureShareList,
  dealer.public_key_package
);

const ok = verify_group_signature(dealer.public_key_package, message, signature);
console.log("signature valid:", ok);
```

## Publication npmjs

```bash
cd pkg
npm publish --access public
```

Le nom publié est basé sur `name` dans `Cargo.toml` (`frost-ed25519-blake2b-wasm`),
ou `@scope/frost-ed25519-blake2b-wasm` si `--scope` est utilisé.

# Servizi Pinless CIE: cie-nis-java-sdk
Cie-Nis-java-sdk è una SDK sviluppata in linguaggio Java che permette di avviare un protocollo di verifica del NIS, Numero Identificativo Servizi, associato ad ogni carta d'identità elettronica (CIE 3.0). Il NIS è univoco per ogni CIE, è a lettura libera e non è riconducibile direttamente al titolare della stessa. La SDK consente di controllare l'autenticità e l'originalità della CIE 3.0 e di convalidare il NIS. E' possibile così utilizzare la CIE per un servizio pinless, ovvero un servizio che non necessita del PIN per la lettura della carta.

# Caso d'uso
Un servizio pinless tramite CIE permette di utilizzare la carta come strumento unico di accesso a molteplici servizi che richiedono un'abilitazione alla fruizione degli stessi, come accesso a mezzi di trasporto, luoghi di lavoro, luoghi pubblici, etc...
L'abilitazione per la fruizione del servizio si compone di due fasi: una di *Enrollment* e una di *Accesso*.
La fase di Enrollment, sviluppata nella SDK, verificata l’autenticità e l’originalità della CIE, restituisce il NIS e l'Hash della chiave pubblica dei servizi H(KPUB). L'integratore del servizio potrà così abilitare la CIE all’uso del proprio servizio, associando l'output restituito dalla SDK all'utente.

La fase di accesso consente all'utente, precedentemente registratosi nella fase di Enrollment, di utilizzare la CIE per accedere al servizio pinless. L'accesso avviene, ad esempio, su un tornello che, verificata l'originalità della CIE mediante i dati salvati in fase di Enrollment, ne autorizza l'accesso.

# Requisiti tecnici
CieNis-java-sdk è strutturata per un'applicazione Desktop e richiede l'installazione di Java SE 15 o superiore. La sdk richiede la dipendenza esterna della libreria BouncyCastle, reperibile in [questa](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on/1.64) repository pubblica.

# Requisiti di integrazione
CieNis-java-sdk necessita di un lettore NFC USB correttamente installato.

# Come si usa
Il manuale che descrive i protocolli operativi del flusso implementato in questa sdk sono presenti in questa [pagina](https://docs.italia.it/italia/cie/cie-accessi-pinless-manuale-docs/it/stabile/index.html). Questa repository integra una classe di esempio, la `TestNisAuthenticated.java`, che integra la SDK. La classe inoltre mostra come utilizzare i metodi: **enroll** e **access**.

# Configurazione
La sdk va importata nel proprio progetto e occorre inizializzarla, controllando che sia correttamente configurata utilizzando il codice seguente:
```sh
NisSdk nisSdk = new TestNisAuthenticated().initSdk();

if(nisSdk.isReady()){
    //metodo per eseguire la registrazione
    nisSdk.enroll();

    //metodo che mostra le operazioni di accesso da eseguire al tornello
    nisSdk.access();
}

public NisSdk initSdk() {
  return new NisSdk(new NfcTerminalImpl(), this, true);
}
```
E' possibile configurare il livello di log desiderato tramite il parametro `isLogEnabled` nel costruttore della classe `NisSdk`.
Per usare la libreria occorre implementare i metodi dell'interfaccia `NisSdkCallback`. Nel metodo dell'interfaccia **onSucccess** viene restituto l'output validato, nel caso di errore invece viene restituto un'eccezione nel metodo **onError**.

# Licenza
Il codice sorgente è rilasciato sotto licenza BSD (codice SPDX: BSD-3-Clause).

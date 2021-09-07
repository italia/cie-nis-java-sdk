# Servizi Pinless CIE: cie-nis-java-sdk
Cie-Nis-java-sdk è una SDK sviluppata in linguaggio Java che permette di avviare un protocollo di verifica del NIS, Numero Identificativo Servizi, associato ad ogni carta d'identità elettronica (CIE 3.0). Il NIS è univoco per ogni CIE, è a lettura libera e non è riconducibile direttamente al titolare della stessa. La SDK consente di controllare l'autenticità e l'originalità della CIE 3.0 e di convalidare il NIS. E' possibile così utilizzare la CIE per un servizio pinless, ovvero un servizio che non necessita del PIN per la lettura della carta.

# Caso d'uso
Un servizio pinless tramite CIE permette di utilizzare la carta come strumento unico di accesso a molteplici servizi che richiedono un'abilitazione alla fruizione degli stessi, come accesso a mezzi di trasporto, luoghi di lavoro, luoghi pubblici, etc...
L'abilitazione per la fruizione del servizio si compone di due fasi: una di *Enrollment* e una di *Accesso*.
La fase di Enrollment, sviluppata nella SDK, verificata l’autenticità e l’originalità della CIE, restituisce il NIS e l'Hash della chiave pubblica dei servizi H(KPUB). L'integratore del servizio potrà così abilitare la CIE all’uso del proprio servizio, associando l'output restituito dalla SDK all'utente.

La fase di accesso consente all'utente, precedentemente registratosi nella fase di Enrollment, di utilizzare la CIE per accedere al servizio pinless. L'accesso avviene, ad esempio, su un tornello che, verificata l'originalità della CIE mediante i dati salvati in fase di Enrollment, ne autorizza l'accesso.

# Requisiti tecnici
CieNis-java-sdk è strutturata per un'applicazione Desktop e richiede l'installazione di Java SE 15 o superiore.

# Requisiti di integrazione
CieNis-java-sdk necessita di un lettore NFC USB correttamente installato.

# Come si usa
La classe principale dell'SDK è la classe **TestIasNFC.java**. Nella classe sono presenti due metodi principali: *enroll* e *access*. I metodi includono gli step da eseguire per le due fasi. Il metodo access viene fornito come riferimento, in quanto gli step inclusi non devono essere eseguiti localmente sulla stessa macchina che esegue l'enrollment.
La gestione degli errori è demandata all'applicazione integrante del Service Provider.
Per ottenere un eseguibile del tipo *.jar*, che esegue automaticamente gli step di verifica del NIS, è necessario lanciare un build della classe.
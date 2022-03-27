# Servizi Pinless CIE: cie-nis-java-sdk
cie-nis-java-sdk è una SDK sviluppata in linguaggio Java che permette di avviare 
un protocollo di verifica del NIS, Numero Identificativo Servizi, associato ad 
ogni carta d'identità elettronica (CIE 3.0). Il NIS è univoco per ogni CIE, è a 
lettura libera e non è riconducibile direttamente al titolare della stessa. 

La SDK consente di controllare l'autenticità e l'originalità della CIE 3.0 e di 
convalidare il NIS. E' possibile così utilizzare la CIE per un servizio pinless, 
ovvero un servizio che non necessita del PIN per la lettura della carta.

## 1. Caso d'uso
Un servizio pinless tramite CIE permette di utilizzare la carta come strumento 
unico di accesso a molteplici servizi che richiedono un'abilitazione alla 
fruizione degli stessi, come accesso a mezzi di trasporto, luoghi di lavoro, 
luoghi pubblici, etc...

L'abilitazione per la fruizione del servizio si compone di due fasi: una di 
*Enrollment* e una di *Accesso*.

La fase di Enrollment, sviluppata nella SDK, verificata l’autenticità e 
l’originalità della CIE, restituisce il NIS e l'Hash della chiave pubblica dei 
servizi H(KPUB). L'integratore del servizio potrà così abilitare la CIE all’uso 
del proprio servizio, associando l'output restituito dalla SDK all'utente.

La fase di accesso consente all'utente, precedentemente registratosi nella fase 
di Enrollment, di utilizzare la CIE per accedere al servizio pinless.
L'accesso avviene, ad esempio, su un tornello che, verificata l'originalità 
della CIE mediante i dati salvati in fase di Enrollment, ne autorizza l'accesso.

## 2. Requisiti tecnici
cie-nis-java-sdk è strutturata per un'applicazione Desktop e richiede 
l'installazione di Java SE 15 o superiore. La sdk richiede l'unica dipendenza 
esterna, ovvero, BouncyCastle, dipendenza inserita nel pom.xml.

## 3. Requisiti di integrazione
cie-nis-java-sdk necessita di un lettore NFC USB correttamente installato.

## 4. Build del progetto
Per la build dell'SDK è possibile procedere seguendo gli step indicati a seguire.
Il progetto è basato su Maven; non è necessario disporre di Maven installato sulla
propria macchina di build, all'interno del progetto è stato inserito il 
Maven Wrapper (sia per sistemi unixlike sia per sistemi Microsoft).

```shell
# 1. Clone del repository
$ git clone https://github.com/italia/cie-nis-java-sdk.git

# Build del progetto via maven
$ cd cie-nis-java-sdk

# Nel caso in cui abbiate installato Maven 3.x
$ mvn clean package

# Nel caso del Maven Wrapper
$ ./mvnw clean package

# Install dell'SDK sul proprio respository Maven locale
$ ./mvnw install
```

Al termine della procedura di build e packaging, all'interno della directory 
`target` saranno disponibili due jar:
1. cie-nis-java-sdk-<version>.jar (esempio: cie-nis-java-sdk-1.0.0-SNAPSHOT.jar)
2. cie-nis-java-sdk-<version>-jar-with-dependencies.jar (esempio: cie-nis-java-sdk-1.0.0-SNAPSHOT-jar-with-dependencies.jar)

Il secondo jar è la versione _fat_, ovvero, il jar contenente la dipendenza di 
BouncyCastle.

L'installazione dell'SDK sul repository locale Maven (vedi comando `./mvnw install`),
fa in modo che possiate utilizzare l'SDK come dipendenza all'interno dei vostri
progetti.

## 5. Come funziona il processo CIE Pinless
Il manuale che descrive i protocolli operativi del flusso implementato in questa 
sdk sono presenti in questa [pagina](https://docs.italia.it/italia/cie/cie-accessi-pinless-manuale-docs/it/stabile/index.html). 
All'interno del progetto è presente una classe di esempio, la `TestNisAuthenticated.java`, 
che integra la SDK. La classe mostra come utilizzare i metodi: 
**enroll** e **access**.

```shell
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

E' possibile configurare il livello di log desiderato tramite il parametro
`isLogEnabled` nel costruttore della classe `NisSdk`.

Per usare la libreria occorre implementare i metodi dell'interfaccia `NisSdkCallback`.
Nel metodo dell'interfaccia **onSucccess** viene restituto l'output validato,
nel caso di errore invece viene restituto un'eccezione nel metodo **onError**.

Potreste eseguire un primo veloce test di funzionamento della classe di esempio
`TestNisAuthenticated.java` eseguendo il comando mostrato a seguire. Prima di 
eseguire il comando ricordate di collegare il lettore NFC alla porta USB e di 
fare la build dell'SDK.

```shell
# Esecuzione del programma di esempio TestNisAuthenticated che esegue i due processi:
# enroll e access.
$ java -cp target/cie-nis-java-sdk-1.0.0-SNAPSHOT-jar-with-dependencies.jar it.ipzs.cie.nis.samples.TestNisAuthenticated
```

Se tutto va come deve, dovreste ottenere un output simile a quello mostrato a 
seguire.

```shell
...

[SDK-NIS-JAVA]VERIFICA CATENA CERTIFICATI...
[SDK-NIS-JAVA]autorità certificante del ds: D11A505E15ADEA5A61779CA4A2A991EC3949D1F9
[SDK-NIS-JAVA]
**************************************************************************
ID SERVIZI(NIS): 383234343636393939303639
CHIAVE PUBBLICA SERVIZI (HashKPub):5B12F2B1B1C0FB510B199D558F9CFB3212D8FC7047241C53F5EB4ECBE058F0BD
INTERNAL AUTHENTICATION: true
DOCUMENT SIGNER CERTIFICATE:
Algoritmo: SHA512withRSAandMGF1
OID: 1.2.840.113549.1.1.10
tipo certificato: X.509
Numero versione: 3
Data scadenza: Fri Oct 15 10:29:18 BST 2032
Data emissione: Thu Jul 15 10:29:18 BST 2021
S/N: 2294862260320152742
Issure: C=IT,O=Ministry of Interior,OU=National Electronic Center of Italian National Police,CN=Italian Country Signer CA
Subject: C=IT,O=Ministry of Interior,OU=Direz. Centr. per i Servizi Demografici - CNSD,2.5.4.5=#13053030303036,CN=eIdentityCardSigner

CSCA CERTIFICATE:
Algoritmo: SHA512withRSAandMGF1
OID: 1.2.840.113549.1.1.10
tipo certificato: X.509
Numero versione: 3
Data scadenza: Wed Jul 25 10:30:43 BST 2035
Data emissione: Wed Apr 29 10:30:43 BST 2020
S/N: 4413561276408245722
Issure: C=IT,O=Ministry of Interior,OU=National Electronic Center of Italian National Police,CN=Italian Country Signer CA
Subject: C=IT,O=Ministry of Interior,OU=National Electronic Center of Italian National Police,CN=Italian Country Signer CA

**************************************************************************
NIS : 824466999069
HASH CHIAVE PUBBLICA SERVIZI : 5B12F2B1B1C0FB510B199D558F9CFB3212D8FC7047241C53F5EB4ECBE058F0BD

...

```

## 5. Integrazione sui propri progetti
Per utilizzare l'SDK all'interno dei propri progetti, è più che sufficiente aggiungere
la dipendenza sul proprio pom.xml o gradle. A seguire un esempio per Maven e 
successivamente per Gradle

```xml
...

<dependencies>
	<dependency>
		<groupId>it.ipzs.cie.nis</groupId>
		<artifactId>cie-nis-java-sdk</artifactId>
		<version>1.0.0-SNAPSHOT</version>
	</dependency>
</dependencies>

...
```

Dipendenza da aggiungere su progetti che utilizzano Gradle come sistema di build 
e gestione delle dipendenze.

```groovy
implementation 'it.ipzs.cie.nis:cie-nis-java-sdk:1.0.0-SNAPSHOT'
```


## 6. Licenza
Il codice sorgente è rilasciato sotto licenza BSD (codice SPDX: BSD-3-Clause).

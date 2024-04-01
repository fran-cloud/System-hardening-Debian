# Secure-Boot-Debian-10
In questo progetto viene descritta la procedura per abilitare UEFI Secure Boot su una distribuzione Debian 10. Esistono diversi modi per farlo e qui ne vengono presentati due, entrambi basati sull'utilizzo di Shim.


## Lab setup
La procedura qui descritta è stata testata utilizzando una virtual machine (VM) creata con VirtualBox versione 7. È importante utilizzare questa vesrione se si è interessati ad integrare il secure boot con l'utilizzo di un modulo TPM al fine di conservare le chiavi private in modo sicuro. Le versioni più recenti di VirtualBox consentono infatti di abilitare il modulo TPM dalle impostazioni della VM, in modo da emulare un modulo TPM hardware. È stata utilizzata una distro Debian 10.13.0-amd64.

## Procedura
Quando si crea una nuova virtual machine, VirtualBox richiede delle informazioni preliminari. In questa fase occorre selezionare il flag *Abilita EFI*.
Dopo aver effettuato queste prime configurazioni, prima di avviare la VM e procedere con l'installazione di Debian, è necedssario aprire le impostazioni della VM e sotto la voce *Sistema* selezionare la versione di TPM da utilizzare (nel mio caso ho scelto 2.0) e abilitare il Secure Booot come mostrato nelle seguenti immagini.


A questo punto è possibile procedere con l'installazione di Debian.

Ad installazione completata il secure boot è già funzionante e fa affidamento su chiavi presenti di default nel firmaware (in genere chiavi Microsoft e chiavi del produttore della scheda madre) e su Shim. Quest'ultimo è firmato da Microsoft e ingloba la chiave pubblica di Debian che viene usata per verificare i componenti successivi (boot loader GRUB, Kernel, initrd).
Ci sono quattro tipi di chiavi di avvio sicuro integrate nel firmware:

**Database Key (db):** sono le chiavi pubbliche corrispondenti alle chiavi private utilizzate per firmare i file binari quali bootloader, kernel ecc. Possono esserci più chiavi db. La maggior parte dei computer viene fornita con due chiavi Microsoft installate. Microsoft ne utilizza una per sé e l'altra per firmare software di terze parti come Shim.

**Forbidden Signature Key (dbx):** contiene chiavi o hash corrispondenti a malware noti in modo da impedirne l'esecuzione.

**Key exchange key (KEK):** possono essere anche più chiavi e vengono utilizzate per firmare le chiavi da immettere in db e dbx in modo che il firmware le accetti come valide. 

**Platform Key (PK):** è una sola ed è usata per firmare le chiavi KEK in modo che siano accettate come valide. Generalmente questa chiave è fornita dal produttore della scheda madre.

A queste quattro tipologie se ne aggiunge una quinta che non appartiene alla parte standard di Secure Boot ma è relativa all'uso di Shim. Si tratta delle chiavi **Machine Owner Key (MOK)**. Sono equivalenti alle chiavi db e possono essere usate per firmare boot loader e altri eseguibili EFI. Quando si vuole ricompilare il kernel o utilizzare un modulo non firmato da Debian occorre creare una nuova chiave, aggiungerla alle chiavi MOK e utilizzarla per firmare il modulo che ci interessa, altrimenti tale modulo non può essere caricato.

È possibile dare un'occhiata alle chiavi presenti nel firmware installando il pacchetto *efitools* con:
```
apt install efitools
```
ed eseguendo il comando:
```
efi-readvar
```

Come è possibile notare, nel mio caso è presente una chiave PK appartenente a Oracle, una chiave KEK e due chiavi db appartenenti a Microsoft. Per visualizzare invece le chiavi MOK è possibile utilizzare l'utility mokutil con il comando:
```
mokutil --list-enrolled
```
L'unica chiave MOK presente di default è quella di Debian.

### Creare e registrare la nostra chiave MOK
Per creare una nostra chiave MOK è possibile utilizzare openssl:
```
mkdir -p /var/lib/shim-signed/mok

cd /var/lib/shim-signed/mok/

openssl req -nodes -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -days 36500 -subj "/CN=My Name/"

openssl x509 -inform der -in MOK.der -out MOK.pem
```

Occorre poi registrare la chiave appena creata:
```
mokutil --import /var/lib/shim-signed/mok/MOK.der
```
All'esecuzione di questo comando, viene richiesto il settaggio di una password monouso da usare al successivo riavvio per confermare la registrazione della chiave. Riavviando, quindi, verrà eseguito il MOK manager come mostrato di seguito. Dal menù mostrato è possibile confermare la registrazione della chiave appena creata con *Enroll MOK* >> *Continue* >> *Yes* >> *[Password scelta]*.

Al riavvio, eseguendo di nuovo il comando `mokutil --list-enrolled` oltre alla chiave Debian comparirà anche la nostra chiave.
Questa chiave ora può essere utilizzata per firmare i moduli kernel che ci interessa caricare e che non sono già firmati da Debian o per ricompilare il Kernel in base alle nostre esigenze e firmalo in modo da verificarlo ad ogni avvio.

### Test
Per verificare che tutto funzioni correttamente è possibile scaricare un modulo del kernel Linux non firmato da Debian, compilarlo e provare a caricarlo. Per fare ciò utilizzo il pacchetto dahdi-source. È possibile installare tale pacchetto con `apt install dahdi-source`. Dopo l'installazione, in */usr/src/* viene memorizzato un file .tar.bz2 contenente i sorgenti del modulo. 

*(Per la compilazione del modulo kernel è necessario il pacchetto linux-headers corrispondente alla versione linux in uso, installabile con `apt install linux-headers-*`).*

Occorre quindi estrarre il contenuto del file .tar.bz2 con:
```
tar -jxvf dahdi.tar.bz2
```
Dopodiché entrare nella cartella */modiles/dahdi/* ed eseguire:
```
make
make install
make config
```
 
Se ora eseguiamo il comando `sudo modinfo dahdi` si può vedere che non è presente nessuna firma. Se si prova a caricarlo con `sudo modprobe dahdi` viene restituito un errore.

Andiamo quindi a firmare il modulo con la nostra chiave MOK utilizzando lo script *sign-file* fornito da Debian.
```
/usr/src/linux-kbuild-4.19/scripts/sign-file sha256 /var/lib/shim-signed/mok/MOK.priv /var/lib/shim-signed/mok/MOK.der /lib/modules/4.19.0-26-amd64/dahdi/dahdi.ko
```

Eseguendo ora `sudo modinfo dahdi` vediamo che il modulo risulta firmato con la nostra chiave. Eseguendo quindi `sudo modprobe dahdi` , il caricamento andrà a buon fine. Infatti lanciando il comando `lsmod | grep dahdi` comaparirà il nostro mosulo.

## Maggiore controllo sul sistema
Per avere un maggiore controllo sul sistema, è possibile sostituire le chiavi PK, KEK e db presenti nel firmware con delle chiavi create da noi. In questo modo verrà eseguito solo il software firmato con le nostre chiavi. Per fare ciò occorre creare tre nuove chiavi e, siccome programmi diversi richiedono formati diversi, si ha la necessità di avere più formati. Tutte le operazioni necessarie possono essere automatizzate con il seguente script.
```bash
#!/bin/bash

#Create keys
openssl req -new -x509 -newkey rsa:2048 -subj "/CN=Genio PK/" -keyout PK.key \
        -out PK.crt -days 3650 -nodes -sha256
openssl req -new -x509 -newkey rsa:2048 -subj "/CN=Genio KEK/" -keyout KEK.key \
        -out KEK.crt -days 3650 -nodes -sha256
openssl req -new -x509 -newkey rsa:2048 -subj "/CN=Genio DB/" -keyout DB.key \
        -out DB.crt -days 3650 -nodes -sha256

#Create DER version
openssl x509 -in PK.crt -out PK.cer -outform DER
openssl x509 -in KEK.crt -out KEK.cer -outform DER
openssl x509 -in DB.crt -out DB.cer -outform DER

apt install uuid-runtime
uuidgen --random > GUID.txt

#Convert a certificate into a EFI signature list
cert-to-efi-sig-list -g "$(< GUID.txt)" PK.crt PK.esl
cert-to-efi-sig-list -g "$(< GUID.txt)" KEK.crt KEK.esl
cert-to-efi-sig-list -g "$(< GUID.txt)" DB.crt DB.esl

#Sign EFI signature list
sign-efi-sig-list -g "$(< GUID.txt)" -k PK.key -c PK.crt PK PK.esl PK.auth
sign-efi-sig-list -g "$(< GUID.txt)" -a -k PK.key -c PK.crt KEK KEK.esl KEK.auth
sign-efi-sig-list -g "$(< GUID.txt)" -a -k KEK.key -c KEK.crt DB DB.esl DB.auth
```

Una volta eseguito questo script, le chiavi create devono essere registrate all'interno del firmware. A tale scopo è necessario copiare i file PK, KEK e DB con estensione .cer all'interno della partizione EFI (*/boot/efi/EFI/debia/*) e riavviare il pc per entrare nel menù UEFI. Da questo menù è possibile seguire la seguente procedura: *Device Manager* >> *Secure Boot Configuration* >> *Secure Boot Mode* >> Selezionare *Custom Mode*. A questo punto comparirà il menù *Custom Secure Boot Options*. Entrando in questo menù si possono gestire le chiavi presenti nel firmware. A partire dalla chiave DB si va quindi ad eliminare la chiave esistente (*Delete key* >> Premere *Invio* in corrispondenza della chiave da eliminare) e ad aggiungere la chiave creata da noi (*Enroll key* >> *Enroll key using file* >> Selezionare il volume mostrato >> *EFI* >> *debian* >> *DB.cer*). Salvare le modifiche e ripetere la procedura anche per le chiavi KEK e PK.

Al riavvio del sistema comparirà una finestra di errore. Questo perché avendo sostituito la chiave db di Microsoft, Shim non risulta più verificato e la sua esecuzione viene bloccata. Occorre spegnere la VM e disabilitare il Secure Boot dalle impostazioni affinché il sistema possa essere avviato correttamente. Una volta avviato il sistema è possibile varificare che le nostre chiavi siano state effettivamente registrate nel firmware con il comando `efi-readvar`.

Per far funzionare correttamente il Secure Boot occorre firmare Shim con la nostra chiave db:
```
sbsign --key DB.key --cert DB.crt --output /boot/efi/EFI/debian/shimx64.efi /boot/efi/EFI/debian/shimx64.efi
```
A questo punto è possibile spegnere la VM e abilitare il Secure Boot che funzionerà correttamente.

*NB: è possibile firmmare Shim non appena le chiavi vengono generate; tuttavia in questo caso si è preferito firmarlo in seguito alla sostituzione delle chiavi nel firmware per evidenziare il corretto funzionamento di Secure Boot che blocca l'avvio in caso di software non verificato.*

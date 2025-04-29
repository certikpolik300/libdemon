clear
mkdir Tools
clear 
echo -e '\033[31;40;1m 
  █████╗ ██╗             ████████╗ ██████╗  ██████╗ ██╗
 ██╔══██╗██║             ╚══██╔══╝██╔═══██╗██╔═══██╗██║
 ███████║██║     ███████╗   ██║   ██║   ██║██║   ██║██║
 ██╔══██║██║     ╚══════╝   ██║   ██║   ██║██║   ██║██║
 ██║  ██║███████╗           ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═╝  ╚═╝╚══════╝           ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ v4
  Autor: 4lbH4cker
  GitHub: https://github.com/4lbH4cker
\033[33;4mVerze:\033[0m 4            \033[33;4mCTRL+C:\033[0m ukončit          \033[33;4mAutor:\033[0m 4lbH4cker

\e[37m[1]\e[36m Požadavky a aktualizace       \e[37m[2]\e[36m Phishingový nástroj				
\e[37m[3]\e[36m Webová kamera hack           \e[37m[4]\e[36m Subscan			
\e[37m[5]\e[36m Gmail Bomber		         \e[37m[6]\e[36m DDOS útok			
\e[37m[7]\e[36m Jak používat ?	             \e[37m[8]\e[36m Odinstalovat stažené programy		
\e[37m[9]\e[36m IP Info	                     \e[37m[10]\e[36m dorks-eye
\e[37m[11]\e[36m HackerPro                     \e[37m[12]\e[36m RED_HAWK
\e[37m[13]\e[36m VirusCrafter                  \e[37m[14]\e[36m Info-Site
\e[37m[15]\e[36m BadMod	                     \e[37m[16]\e[36m Facebash
\e[37m[17]\e[36m DARKARMY                      \e[37m[18]\e[36m AUTO-IP-CHANGER

'

read -p "Zadejte číslo akce: " islem

if [[ $islem == 1 || $islem == 01 ]]; then
    clear
    echo -e "\033[47;31;5m Probíhá instalace požadavků a aktualizací...\033[0m"
    sleep 5
    pkg install git -y
    pkg install python python3 -y
    pkg install pip pip3 -y
    pkg install curl -y
    apt update
    apt upgrade -y
    clear
    echo -e "\033[47;3;35m Aktualizace dokončena...\033[0m"
    sleep 3
    bash alhack.sh

elif [[ $islem == 2 || $islem == 02 ]]; then
    clear
    echo -e "\033[47;3;35m Instalace může chvíli trvat\033[0m"
    sleep 3
    cd Tools
    git clone https://github.com/htr-tech/zphisher
    cd zphisher
    bash zphisher.sh

elif [[ $islem == 3 || $islem == 03 ]]; then
    clear
    cd Tools
    git clone https://github.com/AngelSecurityTeam/Cam-Hackers
    cd Cam-Hackers
    bash cam-hackers.sh

elif [[ $islem == 4 || $islem == 04 ]]; then
    clear
    cd Tools
    git clone https://github.com/ZephrFish/SubDomainizer.git
    cd SubDomainizer
    pip install -r requirements.txt
    python3 SubDomainizer.py

elif [[ $islem == 5 || $islem == 05 ]]; then
    clear
    cd Tools
    git clone https://github.com/4lbH4cker/Gmail-Bomber
    cd Gmail-Bomber
    python3 Gmail-Bomber.py

elif [[ $islem == 6 || $islem == 06 ]]; then
    clear
    cd Tools
    git clone https://github.com/The-L00NIE/Termux-DDOS
    cd Termux-DDOS
    python3 ddos.py

elif [[ $islem == 7 || $islem == 07 ]]; then
    clear
    echo -e "\033[1;36mTento nástroj je vytvořen pro etické hackery."
    echo -e "Nepoužívejte pro nelegální účely!\033[0m"
    sleep 6
    bash alhack.sh

elif [[ $islem == 8 || $islem == 08 ]]; then
    clear
    echo -e "\033[1;31m Odinstalovávám všechny nástroje...\033[0m"
    rm -rf Tools
    sleep 2
    echo -e "\033[1;32m Všechny nástroje byly odstraněny.\033[0m"
    sleep 2
    bash alhack.sh

elif [[ $islem == 9 || $islem == 09 ]]; then
    clear
    cd Tools
    git clone https://github.com/Bhai4You/Termux-IP-Tracer
    cd Termux-IP-Tracer
    bash ip-tracer.sh

elif [[ $islem == 10 ]]; then
    clear
    cd Tools
    git clone https://github.com/UltimateHackers/ReconDog
    cd ReconDog
    python dog.py

elif [[ $islem == 11 ]]; then
    clear
    cd Tools
    git clone https://github.com/4lbH4cker/HackerPro
    cd HackerPro
    python3 HackerPro.py

elif [[ $islem == 12 ]]; then
    clear
    cd Tools
    git clone https://github.com/Tuhinshubhra/RED_HAWK
    cd RED_HAWK
    php rhawk.php

elif [[ $islem == 13 ]]; then
    clear
    cd Tools
    git clone https://github.com/4lbH4cker/VirusCrafter
    cd VirusCrafter
    bash VirusCrafter.sh

elif [[ $islem == 14 ]]; then
    clear
    cd Tools
    git clone https://github.com/Mebus/cupp
    cd cupp
    python3 cupp.py

elif [[ $islem == 15 ]]; then
    clear
    cd Tools
    git clone https://github.com/Lexiie/BadMod
    cd BadMod
    python3 BadMod.py

elif [[ $islem == 16 ]]; then
    clear
    cd Tools
    git clone https://github.com/keralahacker/Facebash.git
    cd Facebash
    bash facebash.sh

elif [[ $islem == 17 ]]; then
    clear
    cd Tools
    git clone https://github.com/cyberknight777/DARKARMY.git
    cd DARKARMY
    bash setup

elif [[ $islem == 18 ]]; then
    clear
    cd Tools
    git clone https://github.com/4lbH4cker/AUTO-IP-CHANGER
    cd AUTO-IP-CHANGER
    bash IPchanger.sh

else
    echo -e "\033[1;31m Neplatná volba, zkuste to znovu.\033[0m"
    sleep 2
    bash alhack.sh
fi

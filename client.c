#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h> 
#include "helpers.h"
#include "requests.h"
#include "parson.h"

// Valorile default folosite in cerintele temei
// pentru a trimite request-uri catre server
#define HOST "34.246.184.49"
#define PORT 8080
#define API_URL "/api/v1/tema"
#define API_AUTH "/auth"
#define API_LIBRARY "/library"
#define AP_JSON "application/json"
#define AUTH_BEARER "Authorization: Bearer "

// Am definit aici toate valorile posibile ale comenzilor
// pentru a le putea folosi in functia nr_comanda
// astfel am evitat if-else in main
#define REGISTER 1
#define LOGIN 2
#define ENTER_LIBRARY 3
#define GET_BOOKS 4
#define GET_BOOK 5
#define ADD_BOOK 6
#define DELETE_BOOK 7
#define LOGOUT 8
#define EXIT 9

// Functie care codifica actiunile posibile
int nr_comanda(char *linie) 
{
    if (strcmp(linie, "register") == 0) return 1;
    if (strcmp(linie, "login") == 0) return 2;
    if (strcmp(linie, "enter_library") == 0) return 3;
    if (strcmp(linie, "get_books") == 0) return 4;
    if (strcmp(linie, "get_book") == 0) return 5;
    if (strcmp(linie, "add_book") == 0) return 6;
    if (strcmp(linie, "delete_book") == 0) return 7;
    if (strcmp(linie, "logout") == 0) return 8;
    if (strcmp(linie, "exit") == 0) return 9;
    return 0;
}

// Functie care prelucreaza raspunsul primit de la server
// Printeaza raspunsul si, daca exista, eroarea
// Foloseste functiile pentru extragerea JSON-ului
void print_raspuns(char *raspuns) 
{
    char *cod = strstr(raspuns, "HTTP/1.1 ");

    if (cod == NULL) 
    {
        printf("Nu s-a primit raspuns de la server\n");
        return;
    }

    printf("Cod raspuns: ");

    for (char *p = cod; *p != '\n'; p++) 
    {
        printf("%c", *p);
    }

    printf("\n");

    char *json = basic_extract_json_response(raspuns);

    if (json != NULL) 
    {
        JSON_Value *json_value = json_parse_string(json);
        JSON_Object *json_object = json_value_get_object(json_value);

        if (json_object_has_value(json_object, "error"))
        {
            printf("Eroare: %s\n", json_object_get_string(json_object, "error"));
        }
    }

}

// Functie care preia cookie-ul din raspunsul primit de la server
// Returneaza cookie-ul sau NULL daca nu exista
// Foloseste functia strstr pentru a gasi "Set-Cookie: "
char *preia_cookie(char *raspuns) 
{
    char *cookie = strstr(raspuns, "Set-Cookie: ");

    if (cookie == NULL) 
    {
        return NULL;
    }

    cookie += strlen("Set-Cookie: ");
    char *final = strstr(cookie, "\r");

    char *rezultat = (char *)malloc((final - cookie + 1) * sizeof(char));
    strncpy(rezultat, cookie, final - cookie);
    rezultat[final - cookie] = 0;

    return rezultat;
}

// Functie care preia token-ul din raspunsul primit de la server
// Returneaza token-ul sau NULL daca nu exista
// Foloseste functia basic_extract_json_response pentru a extrage JSON-ul
char *preia_token(char *raspuns) 
{
    JSON_Value *json_value = json_parse_string(basic_extract_json_response(raspuns));
    JSON_Object *json = json_value_get_object(json_value);

    char *rezultat = (char *)malloc((strlen(json_object_get_string(json, "token")) + 1) * sizeof(char));

    if (rezultat == NULL) 
    {
        return NULL;
    }


    strcpy(rezultat, json_object_get_string(json, "token"));

    return rezultat;
}

// Functia principala care implementeaza clientul
// Citeste comenzile de la tastatura si le proceseaza
// Foloseste functiile din requests.h si helpers.h
// pentru a trimite request-uri catre server
int main() 
{
    // Variabilele folosite in implementare
    int DIM_MAX_SIR = 500, id;
    char *mesaj = NULL, *raspuns = NULL;
    char *cookie = NULL, *token = NULL;
    char *username, *password;
    char *url, **payload;
    int socket = -1;

    bool logat = false;
    bool biblioteca = false;
    bool iesire = false;

    // Variabilele folosite pentru parsarea raspunsului
    JSON_Value *json_value = NULL;
    JSON_Object *json = NULL;
    JSON_Array *json_array = NULL;

    // Alocare memorie pentru linia citita de la tastatura
    char *linie = NULL;
    linie = (char *)malloc(DIM_MAX_SIR * sizeof(char));
    
    // Citirea primei comenzi de la tastatura
    fgets(linie, DIM_MAX_SIR, stdin);
    linie[strlen(linie) - 1] = 0;

    // Alocare memorie pentru variabilele folosite
    username = (char *)malloc(DIM_MAX_SIR * sizeof(char));
    password = (char *)malloc(DIM_MAX_SIR * sizeof(char));
    url = (char *)malloc(DIM_MAX_SIR * sizeof(char));

    do 
    {
        switch (nr_comanda(linie))
        {
            case REGISTER:
                printf("- Incepe register -\n");

                // Creeam o conexiune cu serverul
                socket = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
                if (socket < 0) 
                {
                    perror("Eroare la open_connection");
                    return -1;
                }

                // Incepem sa completam datele pentru request
                // Username-ul si parola sunt citite de la tastatura
                printf("username=");
                fgets(username, DIM_MAX_SIR, stdin);
                username[strlen(username) - 1] = 0;
                
                // Verificam daca username-ul contine spatii
                for (int i = 0; i < strlen(username); i++) 
                {
                    if (username[i] == ' ') 
                    {
                        printf("Username invalid\n");
                        close_connection(socket);
                        return -1;
                    }
                }

                printf("password=");
                fgets(password, DIM_MAX_SIR, stdin);
                password[strlen(password) - 1] = 0;

                // Verificam daca parola contine spatii
                for (int i = 0; i < strlen(password); i++) 
                {
                    if (password[i] == ' ') 
                    {
                        printf("Password invalid\n");
                        close_connection(socket);
                        return -1;
                    }
                }

                // Initializam un obiect JSON si il completam cu datele citite
                json_value = json_value_init_object();
                json = json_value_get_object(json_value);
                json_object_set_string(json, "username", username);
                json_object_set_string(json, "password", password);
                
                // Construim URL-ul pentru request
                // si completam mesajul pentru request
                strcpy(url, API_URL);
                strcat(url, API_AUTH);
                strcat(url, "/register");

                // Trimitem request-ul catre server
                mesaj = compute_post_request(HOST, url, AP_JSON, json_serialize_to_string(json_value), NULL, 0);
                send_to_server(socket, mesaj);
                raspuns = receive_from_server(socket);

                // Afisam raspunsul primit de la server
                print_raspuns(raspuns);

                // Inchidem conexiunea cu serverul
                close_connection(socket);

                printf("- S-a terminat register -\n");
                break;

            case LOGIN:
                printf("- Incepe login -\n");

                // La fel, creeam o conexiune cu serverul
                socket = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
                if (socket < 0) 
                {
                    perror("Eroare la open_connection");
                    return -1;
                }

                // La fel, completam datele pentru request
                printf("username=");
                fgets(username, DIM_MAX_SIR, stdin);
                username[strlen(username) - 1] = 0;
                
                for (int i = 0; i < strlen(username); i++) 
                {
                    if (username[i] == ' ') 
                    {
                        printf("Username invalid\n");
                        close_connection(socket);
                        return -1;
                    }
                }

                printf("password=");
                fgets(password, DIM_MAX_SIR, stdin);
                password[strlen(password) - 1] = 0;

                for (int i = 0; i < strlen(password); i++) 
                {
                    if (password[i] == ' ') 
                    {
                        printf("Password invalid\n");
                        close_connection(socket);
                        return -1;
                    }
                }

                // Initializam un obiect JSON si il completam cu datele citite
                json_value = json_value_init_object();
                json = json_value_get_object(json_value);
                json_object_set_string(json, "username", username);
                json_object_set_string(json, "password", password);

                // Construim URL-ul pentru request, de data 
                // aceasta folosim /login in loc de /register
                // si completam mesajul pentru request
                strcpy(url, API_URL);
                strcat(url, API_AUTH);
                strcat(url, "/login");

                mesaj = compute_post_request(HOST, url, AP_JSON, json_serialize_to_string(json_value), NULL, 0);
                send_to_server(socket, mesaj);
                raspuns = receive_from_server(socket);
                
                // Afisam raspunsul primit de la server
                print_raspuns(raspuns);

                // Preiau cookie-ul primt de la server
                cookie = preia_cookie(raspuns);

                // Setam variabila logat la true
                logat = true;

                // Inchidem conexiunea cu serverul
                close_connection(socket);

                printf("- S-a terminat login -\n");
                break;

            case ENTER_LIBRARY:
                printf("- Incepe enter_library -\n");

                // Daca nu suntem logati, afisam un mesaj de eroare
                if (!logat) 
                {
                    printf("Nu esti logat\n");
                    break;
                }

                // Same, creeam o conexiune cu serverul
                socket = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                if (socket < 0) 
                {
                    perror("Eroare la open_connection");
                    return -1;
                }

                // Compunem URL-ul pentru request
                strcpy(url, API_URL);
                strcat(url, API_LIBRARY);
                strcat(url, "/access");

                // De data aceasta, avem nevoie de un payload
                // care contine cookie-ul primit la login
                payload = (char **)malloc(1 * sizeof(char *));
                payload[0] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[0], "Cookie: ");
                strcat(payload[0], cookie);

                // Completam mesajul pentru request
                mesaj = compute_get_request(HOST, url, NULL, payload, 1);
                send_to_server(socket, mesaj);
                raspuns = receive_from_server(socket);
                
                // Afisam raspunsul primit de la server
                print_raspuns(raspuns);

                // Preiau token-ul primit de la server
                token = preia_token(raspuns);
                
                // Setam variabila biblioteca la true
                biblioteca = true;

                // In cele din urma, inchidem conexiunea cu serverul
                close_connection(socket);

                printf("- S-a terminat enter_library -\n");
                break;

            case GET_BOOKS:
                printf("- Incepe get_books -\n");

                // Daca nu suntem logati sau nu suntem in biblioteca
                if (!logat) 
                {
                    printf("Nu esti logat\n");
                    break;
                }

                if (!biblioteca) 
                {
                    printf("Nu esti in biblioteca\n");
                    break;
                }

                // Creeam o conexiune cu serverul
                socket = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                if (socket < 0) 
                {
                    perror("Eroare la open_connection");
                    return -1;
                }


                // Compunem URL-ul pentru request
                strcpy(url, API_URL);
                strcat(url, API_LIBRARY);
                strcat(url, "/books");

                // De data aceasta, avem nevoie de un payload mai mare
                payload = (char **)malloc(2 * sizeof(char *));
                
                // Cookie-ul esre primul element din payload
                payload[0] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[0], "Cookie: ");
                strcat(payload[0], cookie);

                // Token-ul este al doilea element din payload
                payload[1] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[1], AUTH_BEARER);
                strcat(payload[1], token);  

                // Completam mesajul pentru request  
                mesaj = compute_get_request(HOST, url, NULL, payload, 2);
                send_to_server(socket, mesaj);
                raspuns = receive_from_server(socket);

                // Afisam raspunsul primit de la server
                print_raspuns(raspuns);

                // Extragem lista de carti din raspuns 
                // folosind functia extract_json_array
                json_value = json_parse_string(extract_json_array(raspuns));
                json_array = json_value_get_array(json_value);

                // Preluam numarul de carti din lista
                int nr_carti = json_array_get_count(json_array);
                
                // Daca nu exista carti, afisam un mesaj
                if (nr_carti == 0) 
                {
                    printf("Nu sunt carti\n");
                } 

                // Altfel, afisam fiecare carte din lista
                else 
                {
                    for (int i = 0; i < nr_carti; i++) 
                    {   
                        // Preluam cartea din pozitia i
                        json = json_array_get_object(json_array, i);
                        printf("Carte %d: title=%s\n", 
                                (int)json_object_get_number(json, "id"),
                                json_object_get_string(json, "title"));
                    }

                }

                // Inchidem conexiunea cu serverul
                close_connection(socket);

                printf("- S-a terminat get_books -\n");
                break;

            case GET_BOOK:
                printf("- Incepe get_book -\n");

                // Daca nu suntem logati sau nu suntem in biblioteca
                if (!logat) 
                {
                    printf("Nu esti logat\n");
                    break;
                }

                if (!biblioteca) 
                {
                    printf("Nu esti in biblioteca\n");
                    break;
                }

                // Creeam o conexiune cu serverul
                socket = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                if (socket < 0) 
                {
                    perror("Eroare la open_connection");
                    return -1;
                }

                // Cerem id-ul cartii de la tastatura
                printf("id=");
                fgets(linie, DIM_MAX_SIR, stdin);
                linie[strlen(linie) - 1] = 0;

                // Verificam daca id-ul este valid
                id = atoi(linie);
                if (id == 0) 
                {
                    printf("ID invalid\n");
                    break;
                }

                // Compunem URL-ul specific pentru cartea cu id-ul cerut
                strcpy(url, API_URL);
                strcat(url, API_LIBRARY);
                strcat(url, "/books/");
                strcat(url, linie);

                // La fel, completam payload-ul pentru request
                payload = (char **)malloc(2 * sizeof(char *));
                payload[0] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[0], "Cookie: ");
                strcat(payload[0], cookie);

                payload[1] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[1], AUTH_BEARER);
                strcat(payload[1], token);

                // Completam mesajul pentru request
                mesaj = compute_get_request(HOST, url, NULL, payload, 2);
                send_to_server(socket, mesaj);
                raspuns = receive_from_server(socket);

                // Afisam raspunsul primit de la server
                print_raspuns(raspuns);

                // Extragem cartea din raspuns
                json_value = json_parse_string(basic_extract_json_response(raspuns));
                json = json_value_get_object(json_value);

                // Daca cartea nu exista, afisam un mesaj
                if (json_object_has_value(json, "error")) 
                {
                    printf("Cartea %d nu exista\n", id);
                }

                // Altfel, afisam cartea
                else 
                {
                    printf("Carte %d: title=%s, author=%s, publisher=%s, genre=%s, page_count=%d\n",
                            (int)json_object_get_number(json, "id"),
                            json_object_get_string(json, "title"),
                            json_object_get_string(json, "author"),
                            json_object_get_string(json, "publisher"),
                            json_object_get_string(json, "genre"),
                            (int)json_object_get_number(json, "page_count"));
                }

                // Inchidem conexiunea cu serverul
                close_connection(socket);

                printf("- S-a terminat get_book -\n");
                break;

            case ADD_BOOK:
                printf("- Incepe add_book -\n");

                // Daca nu suntem logati sau nu suntem in biblioteca
                if (!logat) 
                {
                    printf("Nu esti logat\n");
                    break;
                }

                if (!biblioteca) 
                {
                    printf("Nu esti in biblioteca\n");
                    break;
                }

                // Creeam o conexiune cu serverul
                socket = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                if (socket < 0) 
                {
                    perror("Eroare la open_connection");
                    return -1;
                }

                // Initializam un obiect JSON si il completam cu datele citite
                // care reperezinta o carte
                json_value = json_value_init_object();
                json = json_value_get_object(json_value);

                // Aloca memorie pentru fiecare camp al cartii
                char *title, *author, *genre, *publisher, *page_count;
                title = (char *)malloc(DIM_MAX_SIR * sizeof(char));
                author = (char *)malloc(DIM_MAX_SIR * sizeof(char));
                genre = (char *)malloc(DIM_MAX_SIR * sizeof(char));
                publisher = (char *)malloc(DIM_MAX_SIR * sizeof(char));
                page_count = (char *)malloc(DIM_MAX_SIR * sizeof(char));

                // Citim datele cartii de la tastatura
                printf("title=");
                fgets(title, DIM_MAX_SIR, stdin);
                title[strlen(title) - 1] = 0;
                json_object_set_string(json, "title", title);

                printf("author=");
                fgets(author, DIM_MAX_SIR, stdin);
                author[strlen(author) - 1] = 0;
                json_object_set_string(json, "author", author);

                printf("genre=");
                fgets(genre, DIM_MAX_SIR, stdin);
                genre[strlen(genre) - 1] = 0;
                json_object_set_string(json, "genre", genre);

                printf("publisher=");
                fgets(publisher, DIM_MAX_SIR, stdin);
                publisher[strlen(publisher) - 1] = 0;
                json_object_set_string(json, "publisher", publisher);

                printf("page_count=");
                fgets(page_count, DIM_MAX_SIR, stdin);
                page_count[strlen(page_count) - 1] = 0;
                json_object_set_number(json, "page_count", atoi(page_count));

                // Construim URL-ul pentru request
                if (atoi(page_count) == 0) 
                {
                    printf("Numar de pagini invalid\n");
                    break;
                }

                // Completam mesajul pentru request
                strcpy(url, API_URL);
                strcat(url, API_LIBRARY);
                strcat(url, "/books");

                // Completam payload-ul pentru request
                payload = (char **)malloc(2 * sizeof(char *));
                payload[0] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[0], "Cookie: ");
                strcat(payload[0], cookie);

                payload[1] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[1], AUTH_BEARER);
                strcat(payload[1], token);

                // Trimitem request-ul catre server
                mesaj = compute_post_request(HOST, url, AP_JSON, json_serialize_to_string(json_value), payload, 2);
                send_to_server(socket, mesaj);
                raspuns = receive_from_server(socket);

                // Afisam raspunsul primit de la server
                print_raspuns(raspuns);

                close_connection(socket);

                printf("- S-a terminat add_book -\n");
                break;

            case DELETE_BOOK:
                printf("- Incepe delete_book -\n");

                // Daca nu suntem logati sau nu suntem in biblioteca
                if (!logat) 
                {
                    printf("Nu esti logat\n");
                    break;
                }

                if (!biblioteca) 
                {
                    printf("Nu esti in biblioteca\n");
                    break;
                }

                // Creeam o conexiune cu serverul
                socket = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                if (socket < 0) 
                {
                    perror("Eroare la open_connection");
                    return -1;
                }

                // Cerem id-ul cartii de la tastatura
                printf("id=");
                fgets(linie, DIM_MAX_SIR, stdin);
                linie[strlen(linie) - 1] = 0;

                id = atoi(linie);

                // Verificam daca id-ul este valid
                if (id == 0) 
                {
                    printf("ID invalid\n");
                    break;
                }

                // Construim URL-ul specific pentru cartea cu id-ul cerut
                strcpy(url, API_URL);
                strcat(url, API_LIBRARY);
                strcat(url, "/books/");
                strcat(url, linie);

                // Completam payload-ul pentru request
                payload = (char **)malloc(2 * sizeof(char *));
                payload[0] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[0], "Cookie: ");
                strcat(payload[0], cookie);

                payload[1] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[1], AUTH_BEARER);
                strcat(payload[1], token);

                // Completam mesajul pentru request
                mesaj = compute_delete_request(HOST, url, payload, 2);
                send_to_server(socket, mesaj);
                raspuns = receive_from_server(socket);

                // Afisam raspunsul primit de la server
                print_raspuns(raspuns);

                // Inchidem conexiunea cu serverul
                close_connection(socket);

                printf("- S-a terminat delete_book -\n");
                break;

            case LOGOUT:
                printf("- Incepe logout -\n");

                // Daca nu suntem logati, nu ne putem deloga
                if (!logat) 
                {
                    printf("Nu esti logat\n");
                    break;
                }

                // Creeam o conexiune cu serverul
                socket = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                if (socket < 0) 
                {
                    perror("Eroare la open_connection");
                    return -1;
                }

                // Construim URL-ul pentru request
                strcpy(url, API_URL);
                strcat(url, API_AUTH);
                strcat(url, "/logout");

                // Completam payload-ul pentru request
                payload = (char **)malloc(1 * sizeof(char *));
                payload[0] = malloc(DIM_MAX_SIR * sizeof(char));
                strcpy(payload[0], "Cookie: ");
                strcat(payload[0], cookie);

                // Completam mesajul pentru request
                mesaj = compute_get_request(HOST, url, NULL, payload, 1);
                send_to_server(socket, mesaj);
                raspuns = receive_from_server(socket);

                // Afisam raspunsul primit de la server
                print_raspuns(raspuns);

                // Setam variabilele de stare la false
                logat = false;
                biblioteca = false;

                // Inchidem conexiunea cu serverul
                close_connection(socket);

                printf("- S-a terminat logout -\n");
                break;

            case EXIT:
                // Ne pregatim sa iesim din program
                printf("Iesire...\n");
                free(linie);
                free(username);
                free(password);
                free(url);
                free(mesaj);
                free(raspuns);
                free(cookie);
                free(token);
                
                iesire = true;
                break;

            default:
                printf("Comanda invalida\n");
                break;
        }

        // Citim o noua comanda de la tastatura
        if (!iesire) 
        {
            fgets(linie, DIM_MAX_SIR, stdin);
            linie[strlen(linie) - 1] = 0;
        }
    
    // Cat timp nu am primit comanda de iesire
    } while (!iesire);

    return 0;
}
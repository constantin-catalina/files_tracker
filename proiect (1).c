#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#define PATH_MAXI 100
#define STRING_MAX 30
#define PRSS_MAX 11
#define META_MAX 1000
#define SNAP_MAX 80
#define MAX_LINE_LENGTH 200
#define BUFFER_SIZE 1024

typedef struct {
    long size;
    char last_modified[STRING_MAX];
    char permissions[PRSS_MAX];
    long inode_no;
}Snapshot;

void convert_permissions(mode_t mode, char *permissions) {
   permissions[0] = S_ISDIR(mode) ? 'd' : '-';
   permissions[1] = (mode & S_IRUSR) ? 'r' : '-';
   permissions[2] = (mode & S_IWUSR) ? 'w' : '-';
   permissions[3] = (mode & S_IXUSR) ? 'x' : '-';
   permissions[4] = (mode & S_IRGRP) ? 'r' : '-';
   permissions[5] = (mode & S_IWGRP) ? 'w' : '-';
   permissions[6] = (mode & S_IXGRP) ? 'x' : '-';
   permissions[7] = (mode & S_IROTH) ? 'r' : '-';
   permissions[8] = (mode & S_IWOTH) ? 'w' : '-';
   permissions[9] = (mode & S_IXOTH) ? 'x' : '-';
   permissions[10] = '\0';
}

void update_snapshot_file(char *snapfile, char *namefile, struct stat fileStat) {
    int fd = open(snapfile, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    
    // Verificare eroare deschidere fisier
    
    if (fd == -1) {
        perror("Error opening file!");
        return;
    }

     // Extragere metadate fisier

    time_t now = time(NULL);
    struct tm *timestamp = localtime(&now);
    char timestamp_str[STRING_MAX];
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", timestamp);

    char last_time_str[STRING_MAX];
    struct tm *last_modified = localtime(&(fileStat.st_mtime));
    strftime(last_time_str, sizeof(last_time_str), "%Y-%m-%d %H:%M:%S", last_modified);

    char permissions[PRSS_MAX];
    convert_permissions(fileStat.st_mode, permissions);

    // Afisare metadate fisier
    
    char metadata[META_MAX];
    snprintf(metadata, sizeof(metadata),
             "Timestamp: %s\n"
             "File name: %s\n"
             "Size: %ld bytes\n"
             "Last modified: %s\n"
             "Permissions: %s\n"
             "Inode no: %ld\n",
             timestamp_str,
             namefile, fileStat.st_size,
             last_time_str,
             permissions,
             fileStat.st_ino);

    // Verificare eroare scriere fisier
    
    int ok = write(fd, metadata, strlen(metadata));
    
    if (ok == -1) {
        perror("Error writing to file!");
        exit(EXIT_FAILURE);
    }

    // Verificare eroare inchidere fisier

    if (close(fd) == -1) {
        perror("Error closing file!");
        return;
    }
}

Snapshot read_snapshot(int fd) {
  Snapshot snapshot = {0};
    char buffer[MAX_LINE_LENGTH];
    int i = 0;
    char c;
    
    // Pozitionarea cursorului la inceputul fisierului

    if (lseek(fd, 0, SEEK_SET) == -1) {
        perror("Error seeking to the beginning of the file!");
        exit(EXIT_FAILURE);
    }
    
    // Citire date caracter cu caracter
    
    while (read(fd, &c, 1) > 0) {
        if (c == '\n') {
            buffer[i] = '\0'; 
            i = 0; 
            if (strncmp(buffer, "Size", 4) == 0) {
                snapshot.size = atol(&buffer[6]);
            }
	    else if (strncmp(buffer, "Last modified", 13) == 0) {
                strncpy(snapshot.last_modified, &buffer[15], STRING_MAX - 1);
                snapshot.last_modified[STRING_MAX - 1] = '\0'; 
            }
	    else if (strncmp(buffer, "Permissions", 11) == 0) {
                strncpy(snapshot.permissions, &buffer[13], PRSS_MAX - 1);
                snapshot.permissions[PRSS_MAX - 1] = '\0';
            }
	    else if (strncmp(buffer, "Inode no", 8) == 0) {
                snapshot.inode_no = atol(&buffer[10]);
            }
        }
	else {
          
          // Verificare cazuri overflow

	  if(i < MAX_LINE_LENGTH - 1) {
	    buffer[i++] = c;
	  }
	  else {
	    perror("Buffer overflow!");
	    exit(EXIT_FAILURE);
	  }
        }
    }

    return snapshot;
}

void delete_snapshot_for_deleted_files(char *output_dir) {
    DIR *dir;
    struct dirent *entry;
    char namesnap[SNAP_MAX];
    char originfile[SNAP_MAX];
    struct stat st;

    dir = opendir(output_dir);
    if(dir == NULL) {
        perror("Error opening output directory!");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if((strcmp(entry->d_name,".") == 0) || (strcmp(entry->d_name,"..") == 0)){
            continue;
        }

	// Obtinerea numelui fisierului de snapshot
	
        strcpy(namesnap, output_dir);
        strcat(namesnap, "/");
        strcat(namesnap, entry->d_name);

	// Obtinerea numelui fisierului original - caruia ii s-a facut snapshot

	strcpy(originfile, entry->d_name);
	char *index = strstr(originfile, "_snapshot.txt");
	if(index != NULL) {
	  
	  // Inlocuieste "_snapshot.txt" cu "\0"
	  
	  *index = '\0';
	}

	for(int i = 0; i < strlen(originfile); i++) {
	  if(originfile[i] == '_') {
	    originfile[i] = '/';
	  }
	}

        if(lstat(originfile, &st) != 0) {

	  // Fisierul a fost sters din director => va fi sters snapshot-ul sau

	  if(unlink(namesnap) == -1) {
	    perror("Error deleting snapshot file!");
	    exit(EXIT_FAILURE);
          }
	}
    }

    if(closedir(dir)==-1){
        perror("Error closing output directory!");
        exit(EXIT_FAILURE);
    }
}


void snapshot(char *namefile, char *pathfile, struct stat fileStat, char *output_dir){

   char snapfile[PATH_MAXI];
   char namesnap[SNAP_MAX];

   // Construirea denumirii fisierului pentru snapshot
   
   strcpy(namesnap, pathfile);
   for(int i = 0; i < strlen(pathfile); i++) {
     if(namesnap[i] == '/') {
       namesnap[i] = '_';
     }
   }

   // Construirea fisierelor de snapshot
   
   snprintf(snapfile, sizeof(snapfile), "%s/%s_snapshot.txt", output_dir, namesnap);

   Snapshot old_snapshot;
   Snapshot new_snapshot;

   int prev_fd = open(snapfile, O_RDONLY);
   
   // Daca exista snapshot precedent
   
   if(prev_fd != -1) {

     // Citirea datelor vechi si stocarea lor in struct

     old_snapshot = read_snapshot(prev_fd);
     
     if(close(prev_fd)){
        perror("Error closing file!");
        exit(EXIT_FAILURE);
     }

     // Citirea datelor noi si stocarea lor in struct

     new_snapshot.size = fileStat.st_size;
     strftime(new_snapshot.last_modified, sizeof(new_snapshot.last_modified), "%Y-%m-%d %H:%M:%S", localtime(&(fileStat.st_mtime)));
     convert_permissions(fileStat.st_mode, new_snapshot.permissions);
     new_snapshot.inode_no = fileStat.st_ino;
    
     // Compararea datelor din struct
     
     if (old_snapshot.size != new_snapshot.size || strcmp(old_snapshot.last_modified, new_snapshot.last_modified) != 0 ||
	 strcmp(old_snapshot.permissions, new_snapshot.permissions) != 0 || old_snapshot.inode_no != new_snapshot.inode_no) {
       
        // Update snapshot
        update_snapshot_file(snapfile, namefile, fileStat);
	
     }
   }
   
   // Daca nu exista snapshot precedent
   
   else {

     // Creeaza snapshot initial
     update_snapshot_file(snapfile, namefile, fileStat);
     
   }
   
}

void move_file(char *source_path, char *destination, char *namefile){

  char destination_path[1024];
  sprintf(destination_path, "%s/%s", destination, namefile);
   
  // Mutam fisierul periculor in directorul de izolare
  if (rename(source_path, destination_path) != 0) {
        perror("Error moving file!");
	exit(EXIT_FAILURE);
    }
  
}

int check_missing_permissions(struct stat fileStat){

   // Verificare fisier daca are una sau mai multe permisiuni
  
   if(fileStat.st_mode & S_IRUSR) return 0;
   else if(fileStat.st_mode & S_IWUSR) return 0;
   else if(fileStat.st_mode & S_IXUSR) return 0;
   else if(fileStat.st_mode & S_IRGRP) return 0;
   else if(fileStat.st_mode & S_IWGRP) return 0;
   else if(fileStat.st_mode & S_IXGRP) return 0;
   else if(fileStat.st_mode & S_IROTH) return 0;
   else if(fileStat.st_mode & S_IWOTH) return 0;
   else if(fileStat.st_mode & S_IXOTH) return 0;

   // Fisierul nu a avut nicio permisiune
   return 1;
}

void analyze_malicious_file(char *namefile, char *pathfile, struct stat fileStat,  char *output_dir, char *cwd, char *izolated_space_dir, int *counter){

  int pid, status;
  int pfd[2];
  char script_path[1024];
  char buffer;
  ssize_t bytes_read;
  snprintf(script_path, sizeof(script_path), "%s/script.sh", cwd);

  if(pipe(pfd) == -1){
    perror("Error creating pipe!");
    exit(EXIT_FAILURE);
  }
  
  if((pid = fork()) < 0){
    perror("Error creating analyzing process!");
    exit(EXIT_FAILURE);
  }
  else if(pid == 0){ // Cod fiu
    // Inchid capatul de citire
    if(close(pfd[0])){
      perror("Error closing pipe!");
      exit(EXIT_FAILURE);
    }

    // Redirectioneaza iesirea standard spre pipe
    int newfd;
    if((newfd = dup2(pfd[1],1)) < 0){
	perror("Error creating a duplicate!");
	exit(EXIT_FAILURE);
    }

    // Inchid capatul de scriere
    if(close(pfd[1])){
      perror("Error closing pipe!");
      exit(EXIT_FAILURE);
    }
    
    // Realizarea analizei sintactice
    execlp(script_path, script_path, pathfile, cwd, izolated_space_dir, NULL);

    // Dacă execuția ajunge aici, există o eroare
    perror("Error executing verification script!");
    exit(EXIT_FAILURE);
  }
  else { // Cod parinte
    
    // Inchid capatul de scriere
    if(close(pfd[1])){
      perror("Error closing pipe!");
      exit(EXIT_FAILURE);
    }
    
    waitpid(pid, &status, 0);

    char word[BUFFER_SIZE];
    int word_index = 0;
    
    if (WIFEXITED(status)) {
      int exit_status = WEXITSTATUS(status);

      if(exit_status == 0) {
	while((bytes_read = read(pfd[0], &buffer, 1)) > 0){
	  if (buffer == ' ' || buffer == '\n') {
	    word[word_index] = '\0'; 
	    if (strcmp(word, "SAFE") == 0) {
	      // Fisierul suspectat este sigur -> facem snapshot
	      snapshot(namefile, pathfile, fileStat, output_dir);
	    }
	    else {
	      // Fisierul suspectat este periculos -> il izolam
	      (*counter)++;
	      move_file(word, izolated_space_dir, namefile);
	    }
	    word_index = 0;
	  }
	  else {
	    word[word_index++] = buffer;
	  }
	}
      }
     
      // Inchid capatul de citire
      if(close(pfd[0])){
	perror("Error closing pipe!");
	exit(EXIT_FAILURE);
      }
    }
    
    else {
       perror("Verification script exited abnormally!\n");
       close(pfd[0]);
       exit(EXIT_FAILURE);
    }

  }
}

void parse(char *dirname, char *output_dir, char *cwd, char *izolated_space_dir, int *counter){
  DIR *dir;
  struct dirent *entry;
  struct stat fileStat;
  char pathfile[PATH_MAXI];

  dir = opendir(dirname);
  
  if(dir == NULL){
    perror("Error opening directory!");
    exit(EXIT_FAILURE);
  }

  while ((entry = readdir(dir)) != NULL) {

     if((strcmp(entry->d_name,".") == 0) || (strcmp(entry->d_name,"..") == 0)){
       continue;
     }

     strcpy(pathfile,dirname);
     strcat(pathfile,"/");
     strcat(pathfile, entry->d_name);

     int rez = lstat(pathfile, &fileStat);
     if(rez == -1){
       perror("Error getting file status!");
       exit(EXIT_FAILURE);
     }

     if(S_ISDIR(fileStat.st_mode)){
       parse(pathfile, output_dir, cwd, izolated_space_dir, counter);
     }
     else {
       if(check_missing_permissions(fileStat) == 0){
	 // Fisierul nu este suspect -> facem snapshot
	 snapshot(entry->d_name, pathfile, fileStat, output_dir);
       }
       else {
	 // Fisierul este suspect -> analizam fisierul
	 analyze_malicious_file(entry->d_name, pathfile, fileStat, output_dir, cwd, izolated_space_dir, counter);
       }
     }
     
    }

  if(closedir(dir)==-1){
    perror("Error closing directory!");
    exit(EXIT_FAILURE);
  }

}

int main(int argc, char **argv){

  char *output_dir = NULL;
  char *izolated_space_dir = NULL;
  int index_start = 5; //incepand cu argv[5] se vor citi directoarele
  DIR * dir_t1;
  DIR * dir_t2;
  int pid[10], sorted_pid[10], sorted_status[10];
  int status, j = -1, counter;
  
  if(argc < 6 || argc > 15) {
    perror("Error incorrect number of arguments!");
    exit(EXIT_FAILURE);
  }
 
  for(int i = 5; i < argc - 1; i++) {
    for(int j = i + 1; j < argc; j++) {
      if(strcmp(argv[i],argv[j]) == 0) {
	// Daca argumentele primite nu sunt diferite
	perror("Error repetitive arguments!");
	exit(EXIT_FAILURE);
      }
    }
  }

  // Aflare director curent
  
  char cwd[1024];
  if (getcwd(cwd, sizeof(cwd)) == NULL) {
    perror("getcwd() error");
    exit(EXIT_FAILURE);
  }
  
  // Verificare existenta output_dir dat ca si argument
  
  if (argv[1][0] == '-' && argv[1][1] == 'o') {
    output_dir = argv[2];
  }
  else {
    perror("Incorrect syntax for the running program! (output)");
    exit(EXIT_FAILURE);
  }

  if(output_dir == NULL) {
    perror("Error output directory not specified! (output)");
    exit(EXIT_FAILURE);
  }

  dir_t1 = opendir(output_dir);
  
  if(dir_t1 == NULL){
    perror("Error opening directory! (output)");
    exit(EXIT_FAILURE);
  }

  // Verificare existenta izolated_output_dir dat ca si argument
  
  if (argv[3][0] == '-' && argv[3][1] == 's') {
      izolated_space_dir = argv[4];
  }
  else {
    perror("Incorrect syntax for the running program! (izolated)");
    exit(EXIT_FAILURE);
  }

  if(izolated_space_dir == NULL) {
    perror("Error output directory not specified! (izolated)");
    exit(EXIT_FAILURE);
  }

  dir_t2 = opendir(izolated_space_dir);
  
  if(dir_t2 == NULL){
    perror("Error opening directory! (izolated)");
    exit(EXIT_FAILURE);
  }

  // Parcurgerea recursiva a fiecarui director pentru a face snapshot
  
  for (int i = index_start; i < argc; i++) {

    j++;
    pid[j] = fork();

    if(pid[j] < 0) { // Nu s-a putut crea copilul
      perror("Error creating a child process!");
      exit(EXIT_FAILURE);
    }
    else if(pid[j] == 0){  // Cod fiu
      counter = 0;
      parse(argv[i], output_dir, cwd, izolated_space_dir, &counter);
      exit(counter);
    }
    // Cod parinte
  }
  
  for (int i = index_start; i < argc; i++) {

    int terminated_pid = wait(&status);
    
    if(WIFEXITED(status)) {
      for (int k = 0; k < argc - index_start; k++) {
	if (pid[k] == terminated_pid) {
	  sorted_pid[k] = terminated_pid;
	  sorted_status[k] = WEXITSTATUS(status);
	  break;
	}
      }
    }
    else {
      printf("Child process for %s exited abnormally!", argv[i]);
    }
			 
  }

  for (int i = 0; i < argc - index_start; i++) {
     printf("Procesul copil %d s-a încheiat cu PID-ul %d și cu %d fișiere cu potențial periculos.\n", i+1, sorted_pid[i], sorted_status[i]);
  }

  // Sterge snapshot-urile outdated
  delete_snapshot_for_deleted_files(output_dir);

  //Inchidere directoare output si izolated space

  if(closedir(dir_t1)==-1){
    perror("Error closing directory! (output)");
    exit(EXIT_FAILURE);
  }

  if(closedir(dir_t2)==-1){
    perror("Error closing directory! (izolated)");
    exit(EXIT_FAILURE);
  }
  
  return 0;
}

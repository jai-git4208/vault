#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#define __STDC_WANT_LIB_EXT1__ 1
#include <OpenGL/gl3.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_opengl.h>
#include <SDL2/SDL_ttf.h>
#ifdef __APPLE__
#include <SDL2/SDL_syswm.h>
#include <objc/message.h>
#include <objc/objc-runtime.h>
#endif
#include <string.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/resource.h>

#define VAULT_FILE ".vault"
#define MAGIC "VAULT"
#define MAGIC_LEN 5
#define SALT_LEN 16
#define IV_LEN 16
#define KEY_LEN 32
#define ITERATIONS 100000
#define MAX_BUFFER 65536

// ANSI Color Codes
#define C_RESET "\033[0m"
#define C_RED "\033[1;31m"
#define C_GREEN "\033[1;32m"
#define C_YELLOW "\033[1;33m"
#define C_BLUE "\033[1;34m"
#define C_MAGENTA "\033[1;35m"
#define C_CYAN "\033[1;36m"
#define C_WHITE "\033[1;37m"
#define C_DIM "\033[2m"

void handle_errors() {
  ERR_print_errors_fp(stderr);
  abort();
}

int levenshtein(const char *s1, const char *s2) {
  int len1 = strlen(s1), len2 = strlen(s2);
  int matrix[len1 + 1][len2 + 1];

  for (int i = 0; i <= len1; i++)
    matrix[i][0] = i;
  for (int j = 0; j <= len2; j++)
    matrix[0][j] = j;

  for (int i = 1; i <= len1; i++) {
    for (int j = 1; j <= len2; j++) {
      int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
      int min = matrix[i - 1][j] + 1;
      if (matrix[i][j - 1] + 1 < min)
        min = matrix[i][j - 1] + 1;
      if (matrix[i - 1][j - 1] + cost < min)
        min = matrix[i - 1][j - 1] + cost;
      matrix[i][j] = min;
    }
  }
  return matrix[len1][len2];
}

void copy_to_clipboard(const char *text) {
  FILE *pipe = popen("pbcopy", "w");
  if (pipe) {
    fprintf(pipe, "%s", text);
    pclose(pipe);
  }
}

void clear_clipboard_after(int seconds) {
  if (fork() == 0) {
    sleep(seconds);
    copy_to_clipboard("");
    exit(0);
  }
}

void secure_clear(void *ptr, size_t size) {
  if (ptr == NULL)
    return;
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (size--) {
    *p++ = 0;
  }
}

int derive_key(const char *password, const unsigned char *salt,
               unsigned char *key) {
  if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, ITERATIONS,
                         EVP_sha256(), KEY_LEN, key)) {
    return 0;
  }
  return 1;
}

int vault_encrypt(unsigned char *plaintext, int plaintext_len,
                  unsigned char *key, unsigned char *iv,
                  unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handle_errors();
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handle_errors();
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handle_errors();
  ciphertext_len = len;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handle_errors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int vault_decrypt(unsigned char *ciphertext, int ciphertext_len,
                  unsigned char *key, unsigned char *iv,
                  unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handle_errors();
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handle_errors();
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    return -1;
  plaintext_len = len;
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    return -1;
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

char *load_decrypted_vault(const char *password, unsigned char *out_salt) {
  FILE *f = fopen(VAULT_FILE, "rb");
  if (!f)
    return NULL;

  char magic[MAGIC_LEN];
  if (fread(magic, 1, MAGIC_LEN, f) != MAGIC_LEN ||
      memcmp(magic, MAGIC, MAGIC_LEN) != 0) {
    fclose(f);
    return NULL;
  }

  unsigned char salt[SALT_LEN];
  unsigned char iv[IV_LEN];
  if (fread(salt, 1, SALT_LEN, f) != SALT_LEN) {
    fclose(f);
    return NULL;
  }
  if (fread(iv, 1, IV_LEN, f) != IV_LEN) {
    fclose(f);
    return NULL;
  }
  if (out_salt)
    memcpy(out_salt, salt, SALT_LEN);

  unsigned char ciphertext[MAX_BUFFER];
  int ciphertext_len = fread(ciphertext, 1, MAX_BUFFER, f);
  fclose(f);

  unsigned char key[KEY_LEN];
  if (!derive_key(password, salt, key)) {
    secure_clear(ciphertext, MAX_BUFFER);
    return NULL;
  }

  unsigned char *plaintext = malloc(MAX_BUFFER);
  int plaintext_len =
      vault_decrypt(ciphertext, ciphertext_len, key, iv, plaintext);

  secure_clear(key, KEY_LEN);
  secure_clear(ciphertext, MAX_BUFFER);

  if (plaintext_len < 0) {
    free(plaintext);
    return NULL;
  }
  plaintext[plaintext_len] = '\0';
  return (char *)plaintext;
}

void save_encrypted_vault(const char *password, const char *decrypted_data,
                          const unsigned char *existing_salt) {
  unsigned char salt[SALT_LEN];
  if (existing_salt) {
    memcpy(salt, existing_salt, SALT_LEN);
  } else {
    if (!RAND_bytes(salt, SALT_LEN))
      handle_errors();
  }

  unsigned char iv[IV_LEN];
  if (!RAND_bytes(iv, IV_LEN))
    handle_errors();

  unsigned char key[KEY_LEN];
  if (!derive_key(password, salt, key))
    handle_errors();

  unsigned char ciphertext[MAX_BUFFER];
  int ciphertext_len =
      vault_encrypt((unsigned char *)decrypted_data, strlen(decrypted_data),
                    key, iv, ciphertext);

  secure_clear(key, KEY_LEN);

  FILE *f = fopen(VAULT_FILE, "wb");
  if (!f) {
    perror("Failed to open vault for writing");
    exit(1);
  }
  fwrite(MAGIC, 1, MAGIC_LEN, f);
  fwrite(salt, 1, SALT_LEN, f);
  fwrite(iv, 1, IV_LEN, f);
  fwrite(ciphertext, 1, ciphertext_len, f);
  fclose(f);
}
// this function will disable echo and use termios to display stored password
// for security
void secure_get_password(char *pass, size_t size) {
  struct termios oldt, newt;
  size_t i = 0;
  int c;

  if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
    perror("tcgetattr");
    exit(1);
  }

  newt = oldt;
  newt.c_lflag &= ~(ECHO | ICANON);
  if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
    perror("tcsetattr");
    exit(1);
  }

  while (i < size - 1) {
    c = getchar();
    if (c == '\n' || c == '\r' || c == EOF) {
      break;
    } else if (c == 127 || c == '\b') {
      if (i > 0) {
        i--;
      }
    } else {
      pass[i++] = c;
    }
  }
  pass[i] = '\0';

  // restore terminal settings
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  printf("\n");
}


#ifndef NO_MAIN
#define UI_WIDTH 800.0f
#define UI_HEIGHT 600.0f

typedef struct {
  char service[256];
  char username[256];
  char password[256];
  float anim_hover;
} VaultEntry;

typedef struct {
  int screen;      
  int input_mode; 
  char master_pass[256];
  VaultEntry *entries;
  int entry_count;
  float scroll_offset;
  float target_scroll;
  int selected_idx;
  SDL_Window *window;
  SDL_GLContext gl_context;
  GLuint shader_program;
  GLuint vao, vbo;
  GLuint text_shader_program;
  GLuint text_vao, text_vbo;
  TTF_Font *font_main;
  TTF_Font *font_bold;
  char search_query[256];
  char add_svc[256], add_user[256], add_pass[256];
  char error_msg[256];
  float error_timer;
  float cursor_blink;
  float screen_fade;
  int show_add_modal;
} UIState;

const char *vertex_shader_source =
    "#version 330 core\n"
    "layout (location = 0) in vec2 aPos;\n"
    "layout (location = 1) in vec2 aTex;\n"
    "out vec2 TexCoords;\n"
    "uniform mat4 projection;\n"
    "void main() {\n"
    "    TexCoords = aTex;\n"
    "    gl_Position = projection * vec4(aPos, 0.0, 1.0);\n"
    "}\n";

const char *fragment_shader_source =
    "#version 330 core\n"
    "in vec2 TexCoords;\n"
    "out vec4 FragColor;\n"
    "uniform vec4 color;\n"
    "uniform vec2 center;\n"
    "uniform vec2 size;\n"
    "uniform float radius;\n"
    "void main() {\n"
    "    vec2 pos = (TexCoords - 0.5) * size * 2.0;\n"
    "    vec2 d = abs(pos) - size + radius;\n"
    "    float dist = length(max(d, 0.0)) + min(max(d.x, d.y), 0.0) - radius;\n"
    "    float alpha = 1.0 - smoothstep(0.0, 1.5, dist);\n"
    "    FragColor = vec4(color.rgb, color.a * alpha);\n"
    "}\n";

const char *text_vertex_shader_source =
    "#version 330 core\n"
    "layout (location = 0) in vec4 vertex; // <vec2 pos, vec2 tex>\n"
    "out vec2 TexCoords;\n"
    "uniform mat4 projection;\n"
    "void main() {\n"
    "    gl_Position = projection * vec4(vertex.xy, 0.0, 1.0);\n"
    "    TexCoords = vertex.zw;\n"
    "}\n";

const char *text_fragment_shader_source =
    "#version 330 core\n"
    "in vec2 TexCoords;\n"
    "out vec4 color;\n"
    "uniform sampler2D text;\n"
    "uniform vec4 textColor;\n"
    "void main() {\n"
    "    vec4 sampled = texture(text, TexCoords);\n"
    "    color = vec4(textColor.rgb, textColor.a * sampled.a);\n"
    "}\n";

GLuint compile_shader(GLenum type, const char *source) {
  GLuint shader = glCreateShader(type);
  glShaderSource(shader, 1, &source, NULL);
  glCompileShader(shader);
  return shader;
}

void draw_rounded_rect(UIState *state, float x, float y, float w, float h,
                       float r, SDL_Color color) {
  glUseProgram(state->shader_program);
  glBindVertexArray(state->vao);

  float projection[16] = {
      2.0f / UI_WIDTH, 0,    0, 0, 0, -2.0f / UI_HEIGHT, 0, 0, 0, 0, 1, 0,
      -1.0f,           1.0f, 0, 1};

  glUniformMatrix4fv(glGetUniformLocation(state->shader_program, "projection"),
                     1, GL_FALSE, projection);
  glUniform4f(glGetUniformLocation(state->shader_program, "color"),
              color.r / 255.0f, color.g / 255.0f, color.b / 255.0f,
              color.a / 255.0f);
  glUniform2f(glGetUniformLocation(state->shader_program, "center"),
              x + w / 2.0f, y + h / 2.0f);
  glUniform2f(glGetUniformLocation(state->shader_program, "size"), w / 2.0f,
              h / 2.0f);
  glUniform1f(glGetUniformLocation(state->shader_program, "radius"), r);

  float vertices[] = {x,     y,     0, 0, x + w, y,     1, 0,
                      x + w, y + h, 1, 1, x,     y + h, 0, 1};

  glBindBuffer(GL_ARRAY_BUFFER, state->vbo);
  glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_DYNAMIC_DRAW);
  glDrawArrays(GL_TRIANGLE_FAN, 0, 4);
}

void render_text(UIState *state, TTF_Font *font, const char *text, float x,
                 float y, SDL_Color color) {
  if (!text || strlen(text) == 0)
    return;

  // Use a predictable white color for the surface, we tint it in the shader
  SDL_Surface *surface =
      TTF_RenderUTF8_Blended(font, text, (SDL_Color){255, 255, 255, 255});
  if (!surface)
    return;

  // Convert to a format OpenGL loves :3
  SDL_Surface *converted =
      SDL_ConvertSurfaceFormat(surface, SDL_PIXELFORMAT_ABGR8888, 0);
  if (!converted) {
    SDL_FreeSurface(surface);
    return;
  }

  GLuint texture;
  glGenTextures(1, &texture);
  glBindTexture(GL_TEXTURE_2D, texture);

  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
  glPixelStorei(GL_UNPACK_ROW_LENGTH,
                converted->pitch / converted->format->BytesPerPixel);

  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, converted->w, converted->h, 0,
               GL_RGBA, GL_UNSIGNED_BYTE, converted->pixels);

  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

  // Reset row length for subsequent textures
  glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);

  glUseProgram(state->text_shader_program);
  float projection[16] = {
      2.0f / UI_WIDTH, 0,    0, 0, 0, -2.0f / UI_HEIGHT, 0, 0, 0, 0, 1, 0,
      -1.0f,           1.0f, 0, 1};
  glUniformMatrix4fv(
      glGetUniformLocation(state->text_shader_program, "projection"), 1,
      GL_FALSE, projection);
  glUniform4f(glGetUniformLocation(state->text_shader_program, "textColor"),
              color.r / 255.0f, color.g / 255.0f, color.b / 255.0f,
              color.a / 255.0f);

  float w = (float)surface->w;
  float h = (float)surface->h;
  float vertices[6][4] = {{x, y + h, 0.0f, 1.0f},     {x + w, y, 1.0f, 0.0f},
                          {x, y, 0.0f, 0.0f},         {x, y + h, 0.0f, 1.0f},
                          {x + w, y + h, 1.0f, 1.0f}, {x + w, y, 1.0f, 0.0f}};

  glBindVertexArray(state->text_vao);
  glBindBuffer(GL_ARRAY_BUFFER, state->text_vbo);
  glBufferSubData(GL_ARRAY_BUFFER, 0, sizeof(vertices), vertices);
  glDrawArrays(GL_TRIANGLES, 0, 6);

  glBindVertexArray(0);
  glBindTexture(GL_TEXTURE_2D, 0);
  glDeleteTextures(1, &texture);
  SDL_FreeSurface(converted);
  SDL_FreeSurface(surface);
}

void draw_grid(UIState *state) {
  SDL_Color grid_color = {226, 232, 240, 255}; // slate-200
  float step = 40.0f;
  for (float x = 0; x < UI_WIDTH; x += step) {
    draw_rounded_rect(state, x, 0, 1, UI_HEIGHT, 0, grid_color);
  }
  for (float y = 0; y < UI_HEIGHT; y += step) {
    draw_rounded_rect(state, 0, y, UI_WIDTH, 1, 0, grid_color);
  }
}

void gui_render(UIState *state) {
  glClearColor(0.97f, 0.98f, 1.0f, 1.0f); // slate-50
  glClear(GL_COLOR_BUFFER_BIT);
  glEnable(GL_BLEND);
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

  draw_grid(state);

  SDL_Color bg_card = {255, 255, 255, 255};
  SDL_Color card_border = {226, 232, 240, 255};
  SDL_Color shadow = {0, 0, 0, 15};
  SDL_Color text_main = {15, 23, 42, 255};   // slate-900
  SDL_Color text_sec = {100, 116, 139, 255}; // slate-500
  SDL_Color primary = {79, 70, 229, 255};    // indigo-600
  SDL_Color error_red = {239, 68, 68, 255};

  int show_cursor = (SDL_GetTicks() / 500) % 2;

  if (state->screen == 0) { // Login
    // Shadow
    draw_rounded_rect(state, UI_WIDTH / 2.0f - 176, UI_HEIGHT / 2.0f - 116, 360,
                      240, 24.0f, shadow);
    // Card
    draw_rounded_rect(state, UI_WIDTH / 2.0f - 180, UI_HEIGHT / 2.0f - 120, 360,
                      240, 24.0f, bg_card);
    draw_rounded_rect(state, UI_WIDTH / 2.0f - 180, UI_HEIGHT / 2.0f - 120, 360,
                      240, 24.0f, card_border); // Border simulation

    render_text(state, state->font_bold, "Vault Login", UI_WIDTH / 2.0f - 160,
                UI_HEIGHT / 2.0f - 100, text_main);

    if (state->error_timer > 0) {
      render_text(state, state->font_main, state->error_msg,
                  UI_WIDTH / 2.0f - 160, UI_HEIGHT / 2.0f - 70, error_red);
      state->error_timer -= 0.016f;
    }

    render_text(state, state->font_main,
                "Master Password:", UI_WIDTH / 2.0f - 160,
                UI_HEIGHT / 2.0f - 40, primary);

    draw_rounded_rect(state, UI_WIDTH / 2.0f - 160, UI_HEIGHT / 2.0f, 320, 40,
                      12.0f, (SDL_Color){248, 250, 252, 255});
    char stars[256] = {0};
    memset(stars, '*', strlen(state->master_pass));
    render_text(state, state->font_main, stars, UI_WIDTH / 2.0f - 150,
                UI_HEIGHT / 2.0f + 10, text_main);
    if (show_cursor) {
      float tw, th;
      TTF_SizeUTF8(state->font_main, stars, (int *)&tw, (int *)&th);
      draw_rounded_rect(state, UI_WIDTH / 2.0f - 150 + tw,
                        UI_HEIGHT / 2.0f + 10, 2, 20, 0, primary);
    }
  } else { // Dashboard
    // --- draw List First (with clipping) ---
    glEnable(GL_SCISSOR_TEST);
    // glScissor(x, y, width, height) - origin is bottom-left
    glScissor(0, 0, UI_WIDTH, UI_HEIGHT - 95);

    int visible_idx = 0;
    for (int i = 0; i < state->entry_count; i++) {
      if (strlen(state->search_query) > 0 &&
          !strcasestr(state->entries[i].service, state->search_query))
        continue;

      float y = 100 + visible_idx * 95 - state->scroll_offset;
      visible_idx++;
      if (y < -100 || y > UI_HEIGHT)
        continue;

      float h_anim = state->entries[i].anim_hover;
      draw_rounded_rect(state, 44 - h_anim * 8, y + 4,
                        UI_WIDTH - 80 + h_anim * 16, 85, 20.0f, shadow);

      SDL_Color c_bg = {255, 255, 255, 255};
      if (h_anim > 0.1)
        c_bg = (SDL_Color){248, 250, 252, 255};
      draw_rounded_rect(state, 40 - h_anim * 8, y, UI_WIDTH - 80 + h_anim * 16,
                        85, 20.0f, c_bg);
      draw_rounded_rect(state, 40 - h_anim * 8, y, UI_WIDTH - 80 + h_anim * 16,
                        85, 20.0f, card_border);

      render_text(state, state->font_bold, state->entries[i].service,
                  60 - h_anim * 5, y + 15, text_main);
      render_text(state, state->font_main, state->entries[i].username,
                  60 - h_anim * 5, y + 45, text_sec);
    }
    glDisable(GL_SCISSOR_TEST);

    // --- 2. Draw Header Last (stays on top) ---
    // Search Bar - Shifted down for traffic lights
    draw_rounded_rect(state, 40, 45, UI_WIDTH - 200, 45, 12.0f, bg_card);
    draw_rounded_rect(state, 40, 45, UI_WIDTH - 200, 45, 12.0f, card_border);
    render_text(state, state->font_main,
                strlen(state->search_query) ? state->search_query
                                            : "Search vault...",
                55, 58, (strlen(state->search_query) ? text_main : text_sec));
    if (state->input_mode == 1 && show_cursor) {
      float tw, th;
      TTF_SizeUTF8(state->font_main,
                   strlen(state->search_query) ? state->search_query
                                               : "Search vault...",
                   (int *)&tw, (int *)&th);
      draw_rounded_rect(state, 55 + tw, 58, 2, 20, 0, primary);
    }

    // Add Button - Shifted down for traffic lights
    SDL_Color add_btn_color =
        state->show_add_modal ? primary : (SDL_Color){248, 250, 252, 255};
    draw_rounded_rect(state, UI_WIDTH - 150, 45, 110, 45, 12.0f, add_btn_color);
    render_text(state, state->font_main, "+ Add", UI_WIDTH - 120, 58,
                state->show_add_modal ? bg_card : primary);

    if (state->show_add_modal) {
      draw_rounded_rect(state, 0, 0, UI_WIDTH, UI_HEIGHT, 0,
                        (SDL_Color){0, 0, 0, 100}); // Backdrop
      draw_rounded_rect(state, UI_WIDTH / 2 - 196, UI_HEIGHT / 2 - 146, 400,
                        320, 24.0f, shadow);
      draw_rounded_rect(state, UI_WIDTH / 2 - 200, UI_HEIGHT / 2 - 150, 400,
                        320, 24.0f, bg_card);
      render_text(state, state->font_bold, "New Entry", UI_WIDTH / 2 - 170,
                  UI_HEIGHT / 2 - 130, text_main);

      char *labels[] = {"Service:", "Username:", "Password:"};
      char *vals[] = {state->add_svc, state->add_user, state->add_pass};
      for (int i = 0; i < 3; i++) {
        render_text(state, state->font_main, labels[i], UI_WIDTH / 2 - 170,
                    UI_HEIGHT / 2 - 80 + i * 70, primary);
        draw_rounded_rect(state, UI_WIDTH / 2 - 170,
                          UI_HEIGHT / 2 - 55 + i * 70, 340, 35, 10,
                          (SDL_Color){248, 250, 252, 255});
        draw_rounded_rect(state, UI_WIDTH / 2 - 170,
                          UI_HEIGHT / 2 - 55 + i * 70, 340, 35, 10,
                          card_border);

        char *display = vals[i];
        char mask[256] = {0};
        if (i == 2) { // Password field
          memset(mask, '*', strlen(vals[i]));
          display = mask;
        }
        render_text(state, state->font_main, display, UI_WIDTH / 2 - 160,
                    UI_HEIGHT / 2 - 45 + i * 70, text_main);

        if (state->input_mode == i + 2 && show_cursor) {
          float tw, th;
          TTF_SizeUTF8(state->font_main, display, (int *)&tw, (int *)&th);
          draw_rounded_rect(state, UI_WIDTH / 2 - 160 + tw,
                            UI_HEIGHT / 2 - 45 + i * 70, 2, 20, 0, primary);
        }
      }
      render_text(state, state->font_main, "Press ENTER to Save, ESC to Close",
                  UI_WIDTH / 2 - 170, UI_HEIGHT / 2 + 130, text_sec);
    }
  }

  SDL_GL_SwapWindow(state->window);
}

#ifdef __APPLE__
void apply_macos_styling(SDL_Window *window) {
  SDL_SysWMinfo wmInfo;
  SDL_VERSION(&wmInfo.version);
  if (SDL_GetWindowWMInfo(window, &wmInfo)) {
    id nswindow = (id)wmInfo.info.cocoa.window;
    // styleMask |= NSWindowStyleMaskFullSizeContentView (1 << 15)
    SEL selStyleMask = sel_registerName("styleMask");
    SEL selSetStyleMask = sel_registerName("setStyleMask:");
    unsigned long styleMask =
        (unsigned long)((unsigned long (*)(id, SEL))objc_msgSend)(nswindow,
                                                                  selStyleMask);
    styleMask |= (1 << 15);
    ((void (*)(id, SEL, unsigned long))objc_msgSend)(nswindow, selSetStyleMask,
                                                     styleMask);

    ((void (*)(id, SEL, BOOL))objc_msgSend)(
        nswindow, sel_registerName("setTitlebarAppearsTransparent:"), (BOOL)1);
    ((void (*)(id, SEL, long))objc_msgSend)(
        nswindow, sel_registerName("setTitleVisibility:"),
        (long)1); // NSWindowTitleHidden
    ((void (*)(id, SEL, BOOL))objc_msgSend)(
        nswindow, sel_registerName("setMovableByWindowBackground:"), (BOOL)1);
  }
}
#endif

void run_gui() {
  if (SDL_Init(SDL_INIT_VIDEO) < 0)
    return;
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_GL_SetAttribute(SDL_GL_MULTISAMPLEBUFFERS, 1);
  SDL_GL_SetAttribute(SDL_GL_MULTISAMPLESAMPLES, 4);

  UIState state = {0};
  state.window = SDL_CreateWindow("Vault", SDL_WINDOWPOS_CENTERED,
                                  SDL_WINDOWPOS_CENTERED, UI_WIDTH, UI_HEIGHT,
                                  SDL_WINDOW_OPENGL | SDL_WINDOW_SHOWN);
#ifdef __APPLE__
  apply_macos_styling(state.window);
#endif
  state.gl_context = SDL_GL_CreateContext(state.window);
  SDL_GL_SetSwapInterval(1);

  GLuint vs = compile_shader(GL_VERTEX_SHADER, vertex_shader_source);
  GLuint fs = compile_shader(GL_FRAGMENT_SHADER, fragment_shader_source);
  state.shader_program = glCreateProgram();
  glAttachShader(state.shader_program, vs);
  glAttachShader(state.shader_program, fs);
  glLinkProgram(state.shader_program);

  glGenVertexArrays(1, &state.vao);
  glBindVertexArray(state.vao);
  glGenBuffers(1, &state.vbo);
  glBindBuffer(GL_ARRAY_BUFFER, state.vbo);
  glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float), (void *)0);
  glEnableVertexAttribArray(0);
  glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float),
                        (void *)(2 * sizeof(float)));
  glEnableVertexAttribArray(1);

  // Setup text shader
  GLuint tvs = compile_shader(GL_VERTEX_SHADER, text_vertex_shader_source);
  GLuint tfs = compile_shader(GL_FRAGMENT_SHADER, text_fragment_shader_source);
  state.text_shader_program = glCreateProgram();
  glAttachShader(state.text_shader_program, tvs);
  glAttachShader(state.text_shader_program, tfs);
  glLinkProgram(state.text_shader_program);

  glGenVertexArrays(1, &state.text_vao);
  glBindVertexArray(state.text_vao);
  glGenBuffers(1, &state.text_vbo);
  glBindBuffer(GL_ARRAY_BUFFER, state.text_vbo);
  glBufferData(GL_ARRAY_BUFFER, sizeof(float) * 6 * 4, NULL, GL_DYNAMIC_DRAW);
  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, 4 * sizeof(float), 0);

  if (TTF_Init() < 0)
    return;
  const char *font_path = "/System/Library/Fonts/Supplemental/Arial.ttf";
  state.font_main = TTF_OpenFont(font_path, 16);
  state.font_bold = TTF_OpenFont(font_path, 24);

  int running = 1;
  SDL_Event e;
  SDL_StartTextInput();

  while (running) {
    state.scroll_offset += (state.target_scroll - state.scroll_offset) * 0.1f;

    while (SDL_PollEvent(&e)) {
      if (e.type == SDL_QUIT)
        running = 0;
      if (e.type == SDL_MOUSEWHEEL)
        state.target_scroll -= e.wheel.y * 70;

      if (e.type == SDL_MOUSEMOTION && state.screen == 1 &&
          !state.show_add_modal) {
        int my = e.motion.y;
        int hovered_idx = (int)((my - 80 + state.scroll_offset) / 95);
        int count = 0;
        state.selected_idx = -1;
        for (int i = 0; i < state.entry_count; i++) {
          if (strlen(state.search_query) > 0 &&
              !strcasestr(state.entries[i].service, state.search_query))
            continue;
          float target = (count == hovered_idx) ? 1.0f : 0.0f;
          state.entries[i].anim_hover +=
              (target - state.entries[i].anim_hover) * 0.15f;
          if (count == hovered_idx && my > 80)
            state.selected_idx = i;
          count++;
        }
      }

      if (e.type == SDL_MOUSEBUTTONDOWN) {
        int mx = e.button.x, my = e.button.y;
        if (state.screen == 1 && !state.show_add_modal) {
          if (mx >= UI_WIDTH - 150 && mx <= UI_WIDTH - 40 && my >= 20 &&
              my <= 65) {
            state.show_add_modal = 1;
            state.input_mode = 2; // service
            state.add_svc[0] = state.add_user[0] = state.add_pass[0] = '\0';
          } else if (state.selected_idx != -1) {
            copy_to_clipboard(state.entries[state.selected_idx].password);
          } else if (mx >= 40 && mx <= UI_WIDTH - 200 && my >= 20 && my <= 65) {
            state.input_mode = 1; // search
          }
        } else if (state.screen == 1 && state.show_add_modal) {
          for (int i = 0; i < 3; i++) {
            if (mx >= UI_WIDTH / 2 - 170 && mx <= UI_WIDTH / 2 + 170 &&
                my >= UI_HEIGHT / 2 - 55 + i * 70 &&
                my <= UI_HEIGHT / 2 - 20 + i * 70) {
              state.input_mode = i + 2;
            }
          }
        }
      }

      if (e.type == SDL_KEYDOWN) {
        SDL_Keycode sym = e.key.keysym.sym;
        if (sym == SDLK_ESCAPE) {
          if (state.show_add_modal)
            state.show_add_modal = 0;
          else if (state.screen == 1)
            state.search_query[0] = '\0';
          state.input_mode = (state.screen == 0) ? 0 : 1;
        } else if (sym == SDLK_TAB && state.show_add_modal) {
          state.input_mode = (state.input_mode == 4) ? 2 : state.input_mode + 1;
        } else if (sym == SDLK_BACKSPACE) {
          char *target = NULL;
          if (state.input_mode == 0)
            target = state.master_pass;
          else if (state.input_mode == 1)
            target = state.search_query;
          else if (state.input_mode == 2)
            target = state.add_svc;
          else if (state.input_mode == 3)
            target = state.add_user;
          else if (state.input_mode == 4)
            target = state.add_pass;
          if (target && strlen(target) > 0)
            target[strlen(target) - 1] = '\0';
        } else if (sym == SDLK_RETURN) {
          if (state.screen == 0) {
            unsigned char salt[SALT_LEN];
            char *data = load_decrypted_vault(state.master_pass, salt);
            if (data) {
              state.screen = 1;
              state.input_mode = 1;
              state.entry_count = 0;
              state.entries = calloc(MAX_BUFFER / 100, sizeof(VaultEntry));
              char *line = strtok(data, "\n");
              while (line && state.entry_count < (MAX_BUFFER / 100)) {
                sscanf(line, "%s %s %s",
                       state.entries[state.entry_count].service,
                       state.entries[state.entry_count].username,
                       state.entries[state.entry_count].password);
                state.entry_count++;
                line = strtok(NULL, "\n");
              }
              free(data);
            } else {
              strcpy(state.error_msg, "Incorrect Master Password");
              state.error_timer = 2.0f;
            }
          } else if (state.show_add_modal) {
            if (strlen(state.add_svc) > 0 && strlen(state.add_user) > 0 &&
                strlen(state.add_pass) > 0) {
              unsigned char salt[SALT_LEN];
              char *old_data = load_decrypted_vault(state.master_pass, salt);
              if (old_data) {
                char *new_data = malloc(strlen(old_data) + 1024);
                sprintf(new_data, "%s%s %s %s\n", old_data, state.add_svc,
                        state.add_user, state.add_pass);
                save_encrypted_vault(state.master_pass, new_data, salt);

                // Refresh local list
                state.entry_count = 0;
                char *line = strtok(new_data, "\n");
                while (line && state.entry_count < (MAX_BUFFER / 100)) {
                  sscanf(line, "%s %s %s",
                         state.entries[state.entry_count].service,
                         state.entries[state.entry_count].username,
                         state.entries[state.entry_count].password);
                  state.entry_count++;
                  line = strtok(NULL, "\n");
                }
                free(new_data);
                free(old_data);
                state.show_add_modal = 0;
                state.input_mode = 1;
              }
            }
          }
        }
      }
      if (e.type == SDL_TEXTINPUT) {
        char *target = NULL;
        if (state.input_mode == 0)
          target = state.master_pass;
        else if (state.input_mode == 1)
          target = state.search_query;
        else if (state.input_mode == 2)
          target = state.add_svc;
        else if (state.input_mode == 3)
          target = state.add_user;
        else if (state.input_mode == 4)
          target = state.add_pass;
        if (target)
          strncat(target, e.text.text, 255 - strlen(target));
      }
    }
    gui_render(&state);
  }

  if (state.entries) {
    for (int i = 0; i < state.entry_count; i++)
      secure_clear(state.entries[i].password, 256);
    free(state.entries);
  }
  TTF_CloseFont(state.font_main);
  TTF_CloseFont(state.font_bold);
  TTF_Quit();
  glDeleteVertexArrays(1, &state.vao);
  glDeleteBuffers(1, &state.vbo);
  glDeleteVertexArrays(1, &state.text_vao);
  glDeleteBuffers(1, &state.text_vbo);
  SDL_GL_DeleteContext(state.gl_context);
  SDL_DestroyWindow(state.window);
  SDL_Quit();
}

void get_password(char *pass, size_t size) {
  printf("Enter master password: ");
  fflush(stdout);
  secure_get_password(pass, size);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf(C_CYAN
           "Usage: " C_WHITE "vault " C_YELLOW
           "<init|add|list|get|delete|search|copy|interactive|gui>" C_RESET
           " [args]\n");
    return 1;
  }

  // disable core dumps
  struct rlimit limit;
  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  if (setrlimit(RLIMIT_CORE, &limit) != 0) {
    fprintf(stderr, C_DIM "Warning: Failed to disable core dumps" C_RESET "\n");
  }

  char *command = argv[1];

  if (strcmp(command, "gui") == 0) {
    run_gui();
    return 0;
  }

  // lock password buffer in memory to prevent swapping
  char password[256];
  if (mlock(password, sizeof(password)) != 0) {
    fprintf(stderr,
            C_DIM "Warning: Failed to lock password buffer" C_RESET "\n");
  }

  if (strcmp(command, "init") == 0) {
    get_password(password, sizeof(password));
    save_encrypted_vault(password, "", NULL);
    secure_clear(password, sizeof(password));
    printf(C_GREEN "✓ Vault initialized." C_RESET "\n");
    return 0;
  }

  // All other commands require loading the vault
  get_password(password, sizeof(password));
  unsigned char salt[SALT_LEN];
  char *data = load_decrypted_vault(password, salt);
  if (!data) {
    fprintf(stderr, C_RED "✗ Failed to load vault. Incorrect password or "
                          "corrupted file." C_RESET "\n");
    return 1;
  }

  if (strcmp(command, "add") == 0) {
    if (argc != 5) {
      printf(C_CYAN "Usage: " C_WHITE "vault add " C_YELLOW
                    "<service> <user> <pass>" C_RESET "\n");
      secure_clear(data, strlen(data));
      free(data);
      secure_clear(password, sizeof(password));
      return 1;
    }
    char *new_data = malloc(strlen(data) + strlen(argv[2]) + strlen(argv[3]) +
                            strlen(argv[4]) + 10);
    sprintf(new_data, "%s%s %s %s\n", data, argv[2], argv[3], argv[4]);
    save_encrypted_vault(password, new_data, salt);
    printf(C_GREEN "✓ Added entry for " C_CYAN "%s" C_RESET "\n", argv[2]);
    secure_clear(new_data, strlen(new_data));
    free(new_data);
  } else if (strcmp(command, "list") == 0) {
    printf(C_MAGENTA "Stored services:" C_RESET "\n");
    char *line = strtok(data, "\n");
    int count = 0;
    while (line) {
      char s[256], u[256], p[256];
      if (sscanf(line, "%s %s %s", s, u, p) == 3) {
        printf(C_BLUE "  •" C_RESET " %s\n", s);
        count++;
        secure_clear(p, sizeof(p));
      }
      secure_clear(s, sizeof(s));
      secure_clear(u, sizeof(u));
      line = strtok(NULL, "\n");
    }
    if (count == 0)
      printf(C_DIM "  (empty)" C_RESET "\n");
  } else if (strcmp(command, "get") == 0) {
    if (argc != 3) {
      printf(C_CYAN "Usage: " C_WHITE "vault get " C_YELLOW "<service>" C_RESET
                    "\n");
      secure_clear(data, strlen(data));
      free(data);
      secure_clear(password, sizeof(password));
      return 1;
    }
    char *line = strtok(data, "\n");
    int found = 0;
    while (line) {
      char s[256], u[256], p[256];
      if (sscanf(line, "%s %s %s", s, u, p) == 3 && strcmp(s, argv[2]) == 0) {
        printf(C_CYAN "Service:  " C_WHITE "%s" C_RESET "\n", s);
        printf(C_CYAN "Username: " C_WHITE "%s" C_RESET "\n", u);
        printf(C_CYAN "Password: " C_GREEN "%s" C_RESET "\n", p);
        found = 1;
        secure_clear(p, sizeof(p));
        secure_clear(s, sizeof(s));
        secure_clear(u, sizeof(u));
        break;
      }
      secure_clear(p, sizeof(p));
      secure_clear(s, sizeof(s));
      secure_clear(u, sizeof(u));
      line = strtok(NULL, "\n");
    }
    if (!found)
      printf(C_YELLOW "⚠ No entry found for " C_WHITE "%s" C_RESET "\n",
             argv[2]);
  } else if (strcmp(command, "delete") == 0) {
    if (argc != 3) {
      printf(C_CYAN "Usage: " C_WHITE "vault delete " C_YELLOW
                    "<service>" C_RESET "\n");
      secure_clear(data, strlen(data));
      free(data);
      secure_clear(password, sizeof(password));
      return 1;
    }
    char *new_data = calloc(1, MAX_BUFFER);
    char *line = strtok(data, "\n");
    int deleted = 0;
    while (line) {
      char s[256], u[256], p[256];
      if (sscanf(line, "%s %s %s", s, u, p) == 3 && strcmp(s, argv[2]) == 0) {
        deleted = 1;
      } else {
        strcat(new_data, line);
        strcat(new_data, "\n");
      }
      secure_clear(p, sizeof(p));
      secure_clear(s, sizeof(s));
      secure_clear(u, sizeof(u));
      line = strtok(NULL, "\n");
    }
    if (deleted) {
      save_encrypted_vault(password, new_data, salt);
      printf(C_GREEN "✓ Deleted entry for " C_CYAN "%s" C_RESET "\n", argv[2]);
    } else {
      printf(C_YELLOW "⚠ No entry found for " C_WHITE "%s" C_RESET "\n",
             argv[2]);
    }
    free(new_data);
  } else if (strcmp(command, "search") == 0) {
    if (argc != 3) {
      printf(C_CYAN "Usage: " C_WHITE "vault search " C_YELLOW "<query>" C_RESET
                    "\n");
      secure_clear(data, strlen(data));
      free(data);
      secure_clear(password, sizeof(password));
      return 1;
    }
    printf(C_MAGENTA "Search results (fuzzy):" C_RESET "\n");
    char *line = strtok(data, "\n");
    int count = 0;
    while (line) {
      char s[256], u[256], p[256];
      if (sscanf(line, "%s %s %s", s, u, p) == 3) {
        int dist = levenshtein(argv[2], s);
        if (dist <= 2 || strstr(s, argv[2])) {
          printf(C_BLUE "  •" C_RESET " %s (match score: %d)\n", s, dist);
          count++;
        }
        secure_clear(p, sizeof(p));
      }
      secure_clear(s, sizeof(s));
      secure_clear(u, sizeof(u));
      line = strtok(NULL, "\n");
    }
    if (count == 0)
      printf(C_DIM "  No matches found." C_RESET "\n");
  } else if (strcmp(command, "copy") == 0) {
    if (argc != 3) {
      printf(C_CYAN "Usage: " C_WHITE "vault copy " C_YELLOW "<service>" C_RESET
                    "\n");
      secure_clear(data, strlen(data));
      free(data);
      secure_clear(password, sizeof(password));
      return 1;
    }
    char *line = strtok(data, "\n");
    int found = 0;
    while (line) {
      char s[256], u[256], p[256];
      if (sscanf(line, "%s %s %s", s, u, p) == 3 && strcmp(s, argv[2]) == 0) {
        copy_to_clipboard(p);
        printf(C_GREEN "✓ Password for %s copied to clipboard." C_RESET "\n",
               s);
        printf(C_DIM "  (Clipboard will clear in 15 seconds)" C_RESET "\n");
        clear_clipboard_after(15);
        found = 1;
        secure_clear(p, sizeof(p));
        secure_clear(s, sizeof(s));
        secure_clear(u, sizeof(u));
        break;
      }
      secure_clear(p, sizeof(p));
      secure_clear(s, sizeof(s));
      secure_clear(u, sizeof(u));
      line = strtok(NULL, "\n");
    }
    if (!found)
      printf(C_YELLOW "⚠ No entry found for " C_WHITE "%s" C_RESET "\n",
             argv[2]);
  } else if (strcmp(command, "interactive") == 0) {
    printf(C_MAGENTA "Vault Interactive Mode (Timeout: 30s)" C_RESET "\n");
    printf(C_DIM "Type 'exit' to close." C_RESET "\n");

    struct pollfd pfd = {STDIN_FILENO, POLLIN, 0};
    char buf[1024];

    while (1) {
      printf(C_CYAN "vault> " C_RESET);
      fflush(stdout);

      int ret = poll(&pfd, 1, 30000); 
      if (ret == 0) {
        printf("\n" C_YELLOW
               "⚠ Inactivity timeout. Auto-locking vault..." C_RESET "\n");
        break;
      } else if (ret < 0) {
        perror("poll");
        break;
      }

      if (fgets(buf, sizeof(buf), stdin) == NULL)
        break;
      buf[strcspn(buf, "\n")] = 0;

      if (strcmp(buf, "exit") == 0 || strcmp(buf, "quit") == 0)
        break;
      if (strlen(buf) == 0)
        continue;

      
      char *i_argv[10];
      int i_argc = 0;
      char *token = strtok(buf, " ");
      while (token && i_argc < 10) {
        i_argv[i_argc++] = token;
        token = strtok(NULL, " ");
      }

      if (i_argc == 0)
        continue;
      char *i_cmd = i_argv[0];

      if (strcmp(i_cmd, "list") == 0) {
        char *data_copy = strdup(data);
        char *line = strtok(data_copy, "\n");
        while (line) {
          char s[256], u[256], p[256];
          if (sscanf(line, "%s %s %s", s, u, p) == 3) {
            printf(C_BLUE "  •" C_RESET " %s\n", s);
            secure_clear(p, sizeof(p));
          }
          line = strtok(NULL, "\n");
        }
        free(data_copy);
      } else if (strcmp(i_cmd, "get") == 0 && i_argc == 2) {
        char *data_copy = strdup(data);
        char *line = strtok(data_copy, "\n");
        int found = 0;
        while (line) {
          char s[256], u[256], p[256];
          if (sscanf(line, "%s %s %s", s, u, p) == 3 &&
              strcmp(s, i_argv[1]) == 0) {
            printf(C_CYAN "Service:  " C_WHITE "%s" C_RESET "\n", s);
            printf(C_CYAN "Username: " C_WHITE "%s" C_RESET "\n", u);
            printf(C_CYAN "Password: " C_GREEN "%s" C_RESET "\n", p);
            found = 1;
            secure_clear(p, sizeof(p));
            break;
          }
          secure_clear(p, sizeof(p));
          line = strtok(NULL, "\n");
        }
        if (!found)
          printf(C_YELLOW "⚠ No entry found for %s" C_RESET "\n", i_argv[1]);
        free(data_copy);
      } else if (strcmp(i_cmd, "copy") == 0 && i_argc == 2) {
        char *data_copy = strdup(data);
        char *line = strtok(data_copy, "\n");
        int found = 0;
        while (line) {
          char s[256], u[256], p[256];
          if (sscanf(line, "%s %s %s", s, u, p) == 3 &&
              strcmp(s, i_argv[1]) == 0) {
            copy_to_clipboard(p);
            printf(C_GREEN "✓ Password for %s copied to clipboard." C_RESET
                           "\n",
                   s);
            printf(C_DIM "  (Clipboard will clear in 15 seconds)" C_RESET "\n");
            clear_clipboard_after(15);
            found = 1;
            secure_clear(p, sizeof(p));
            break;
          }
          secure_clear(p, sizeof(p));
          line = strtok(NULL, "\n");
        }
        if (!found)
          printf(C_YELLOW "⚠ No entry found for %s" C_RESET "\n", i_argv[1]);
        free(data_copy);
      } else if (strcmp(i_cmd, "search") == 0 && i_argc == 2) {
        char *data_copy = strdup(data);
        char *line = strtok(data_copy, "\n");
        while (line) {
          char s[256], u[256], p[256];
          if (sscanf(line, "%s %s %s", s, u, p) == 3) {
            int dist = levenshtein(i_argv[1], s);
            if (dist <= 2 || strstr(s, i_argv[1])) {
              printf(C_BLUE "  •" C_RESET " %s (match score: %d)\n", s, dist);
            }
            secure_clear(p, sizeof(p));
          }
          line = strtok(NULL, "\n");
        }
        free(data_copy);
      } else {
        printf(C_DIM "Unknown or malformed command. Supported: list, get "
                     "<svc>, copy <svc>, search <svc>, exit" C_RESET "\n");
      }
    }
  } else if (strcmp(command, "export") == 0) {
    printf("{\n  \"entries\": [\n");
    char *line = strtok(data, "\n");
    int first = 1;
    while (line) {
      char s[256], u[256], p[256];
      if (sscanf(line, "%s %s %s", s, u, p) == 3) {
        if (!first)
          printf(",\n");
        printf("    {\"service\": \"%s\", \"username\": \"%s\", \"password\": "
               "\"%s\"}",
               s, u, p);
        first = 0;
        secure_clear(p, sizeof(p));
      }
      secure_clear(s, sizeof(s));
      secure_clear(u, sizeof(u));
      line = strtok(NULL, "\n");
    }
    printf("\n  ]\n}\n");
  } else {
    printf(C_RED "✗ Unknown command: " C_WHITE "%s" C_RESET "\n", command);
    secure_clear(data, strlen(data));
    free(data);
    secure_clear(password, sizeof(password));
    return 1;
  }

  secure_clear(data, strlen(data));
  free(data);
  secure_clear(password, sizeof(password));
  return 0;
}
#endif 

#ifndef OCFBNJ_PIXEL_ENGINE_H
#define OCFBNJ_PIXEL_ENGINE_H

#include <atomic>
#include <chrono>
#include <mutex>
#ifdef STD_SPAN
#include <span>
#else
#include "myspan.h"
#endif
#include <string>
#ifdef STD_STRING_VIEW
#include <string_view>
#else
#include "mystring_view.h"
#endif
#include <thread>
#include <vector>

//#include <pixel_engine/EBO.h>
#include <pixel_engine/Pixel.h>
//#include <pixel_engine/Shader.h>
#include <pixel_engine/TaskQueue.h>
//#include <pixel_engine/Texture.h>
//#include <pixel_engine/VAO.h>
//#include <pixel_engine/VBO.h>

struct GLFWwindow;

class PixelEngine {
public:
    enum class KeyStatus {
        Press,
        Release,
        Repeat,
    };

    // clang-format off
    enum class Key {
        Unknown,
        Space,
        Apostrophe,
        Comma,
        Minus,
        Period,
        Slash,
        Num0, Num1, Num2, Num3, Num4, Num5, Num6, Num7, Num8, Num9,
        Semicolon,
        Equal,
        A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
        LeftBracket,
        Backslash,
        RightBracket,
        GraveAccent,
        World1,
        World2,
        Escape,
        Enter,
        Tab,
        Backspace,
        Insert,
        Delete,
        Right,
        Left,
        Down,
        Up,
        PageUp,
        PageDown,
        Home,
        End,
        CapsLock,
        ScrollLock,
        NumLock,
        PrintScreen,
        Pause,
        F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12, F13, F14, F15, F16, F17, F18, F19, F20, F21, F22, F23, F24, F25,
        Kp0, Kp1, Kp2, Kp3, Kp4, Kp5, Kp6, Kp7, Kp8, Kp9,
        KpDecimal, KpDivide, KpMultiply, KpSubtract, KpAdd, KpEnter, KpEqual,
        LeftShift, LeftControl, LeftAlt, LeftSuper,
        RightShift, RightControl, RightAlt, RightSuper,
        Menu,
    };
    // clang-format on

#ifdef STD_STRING_VIEW
    PixelEngine(int width, int height, std::string_view title, int scale);
#else
    PixelEngine(int width, int height, MyStringView title, int scale);
#endif
    virtual ~PixelEngine() = default;

    //void run();

    void init();
    void loop();
    void exit();

    void setFpsLimit(int value);
    void setFpsUpdateInterval(int ms);
    void setVsyncEnabled(bool enabled);
    void setWindowTitle(const std::string& str);

    Pixel getPixel(int x, int y);
    void drawPixel(int x, int y, Pixel pixel);
#ifdef STD_SPAN
    void drawPixels(std::span<const std::uint8_t> rawPixels);
#else
    void drawPixels(MySpan<const std::uint8_t> rawPixels);
#endif

    virtual void onBegin();
    virtual void onUpdate();
    virtual void onEnd();

    virtual void onKeyPress(Key key);
    virtual void onKeyRelease(Key key);
    virtual void onKeyRepeat(Key key);

    virtual void onSize(int width, int height);
    virtual void onMaximize(bool maximized);
    virtual void onIconify(bool iconified);
    virtual void onFocus(bool focused);
    virtual void onRefresh();

    static void keyCallback(PixelEngine* pixelEngine, int key, int action);

private:
#if STD_CONDITIONAL
    using Clock = std::conditional_t<std::chrono::high_resolution_clock::is_steady,
                                     std::chrono::high_resolution_clock,
                                     std::chrono::steady_clock>;
#else
    using Clock = std::chrono::steady_clock;
#endif

#ifdef OPENGL
    struct GLContext {
        GLContext(int width, int height, std::string_view title);
        ~GLContext();

        GLFWwindow* window;
    };
#endif

    //static void keyCallback(GLFWwindow* window, int key, int scancode, int action, int mods);

    static void framebufferSizeCallback(GLFWwindow* window, int width, int height);
    static void windowSizeCallback(GLFWwindow* window, int width, int height);
    static void windowMaximizeCallback(GLFWwindow* window, int maximized);
    static void windowIconifyCallback(GLFWwindow* window, int iconified);
    static void windowFocusCallback(GLFWwindow* window, int focused);
    static void windowRefreshCallback(GLFWwindow* window);

    void userThread();

    void bindCallback();
    void render();
    void updateFps();

    void runInMainThread(TaskQueue::Task task);
    void runInUserThread(TaskQueue::Task task);

    void assertInMainThread();
    void assertInUserThread();

    int width;
    int height;

    std::string title;

    //GLContext glContext;

    //Shader shader;
    //VAO vao;
    //VBO vbo;
    //EBO ebo;

    std::vector<Pixel> pixels;
    std::vector<Pixel> pixelsCopy; // guard by `mtx`
    //Texture texture;

    Clock::time_point startTime;
    Clock::duration freeTime;

    Clock::duration frameTimeLimit;
    Clock::duration fpsUpdateInterval;

    std::atomic<bool> m_bExit;
    std::mutex mtx; // for `pixelsCopy`
    std::thread* m_pThread = nullptr;

    std::thread::id mainThreadId;
    std::thread::id userThreadId;

    TaskQueue mainThreadQueue;
    TaskQueue userThreadQueue;
};

#endif // OCFBNJ_PIXEL_ENGINE_H

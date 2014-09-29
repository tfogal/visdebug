package gfx

// #include <SDL2/SDL.h>
// #include <SDL2/SDL_opengl.h>
import "C"
import "../msg"
import "github.com/go-gl/gl"
import "github.com/veandco/go-sdl2/sdl"

var gfxfunc = make(chan func())
var gfx = msg.StdChan()
var glctx sdl.GLContext
var window *sdl.Window

// The application's main thread must lock and then call this.
func Main() {
  for f := range gfxfunc {
    f()
  }
  gfx.Trace("gfx shutting down.")
  sdl.GL_DeleteContext(glctx)
  window.Destroy()
}

// Execute a function in the gfx's thread.  Synchronous.
func Exec(f func()) {
  done := make(chan bool, 1)
  gfxfunc <- func() {
    f()
    done <- true
  }
  <- done
}

func Close() {
  close(gfxfunc)
}

func poll() {
  ev := sdl.PollEvent()
  if ev == nil {
    return
  }
  if we, ok := ev.(sdl.WindowEvent) ; ok {
    if we.Type == sdl.QUIT {
      close(gfxfunc)
    }
  }
}

func Context() {
  Exec(func() {
    sdl.GL_SetAttribute(C.SDL_GL_CONTEXT_PROFILE_MASK,
                        C.SDL_GL_CONTEXT_PROFILE_CORE)
    sdl.GL_SetAttribute(C.SDL_GL_CONTEXT_MAJOR_VERSION, 3)
    sdl.GL_SetAttribute(C.SDL_GL_CONTEXT_MINOR_VERSION, 2)
    sdl.GL_SetAttribute(sdl.GL_CONTEXT_DEBUG_FLAG, 1)
    sdl.GL_SetAttribute(sdl.GL_CONTEXT_FLAGS , sdl.GL_CONTEXT_DEBUG_FLAG)
    window = sdl.CreateWindow("vismem", sdl.WINDOWPOS_UNDEFINED,
                              sdl.WINDOWPOS_UNDEFINED,
                              800, 600, sdl.WINDOW_SHOWN | sdl.WINDOW_OPENGL)
    glctx = sdl.GL_CreateContext(window)
    sdl.GL_MakeCurrent(window, glctx)

    if gl.Init() != 0 {
      panic("could not initialize GL")
    }

    gl.ClearColor(0.1, 0.1, 0.3, 0.0)
    gl.Clear(gl.COLOR_BUFFER_BIT)
    //surface := window.GetSurface()
    //rect := sdl.Rect { 0, 0, 200, 200 }
    //surface.FillRect(&rect, 0xffff0000)
  })
}

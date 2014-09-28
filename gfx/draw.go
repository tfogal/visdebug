package gfx

// #include <SDL2/SDL.h>
// #include <SDL2/SDL_opengl.h>
import "C"
import "github.com/go-gl/gl"
import "github.com/veandco/go-sdl2/sdl"

const vertshader = `
#version 150
in vec2 position;

void main() {
  gl_Position = vec4(position, 0.0, 1.0);
}
`
const fragshader = `
#version 150
out vec4 outColor;

void main() {
  outColor = vec4(1.0, 1.0, 1.0, 1.0);
}
`

func flush_errors(pre string) {
  gfx.Trace(pre)
  for {
    errnum := gl.GetError()
    if errnum == 0 {
      return
    }
    gfx.Error("GL error: %v\n", errnum)
  }
}

type Scalar2D interface {
  Pre()
  Render(data []float32, dims [2]uint)
  Post()
}

type s2d struct {
  vertvbo gl.Buffer
  vao gl.VertexArray
  program gl.Program
  quad []float32
}

func ScalarField2D() Scalar2D {
  var s s2d
  return s
}

// creates the static data / OGL objects we need.  Must be called before
// 'Render'.
func (s s2d) Pre() {
  Exec(func() {
    s.vao = gl.GenVertexArray()
    s.vao.Bind()

    flush_errors("pre: start")
    s.vertvbo = gl.GenBuffer()
    s.vertvbo.Bind(gl.ARRAY_BUFFER)
    s.quad = []float32{
       0.9,  0.9,
       0.9, -0.9,
      -0.9, -0.9,
      -0.9,  0.9,
    }
    // unsafe.Sizeof(quad) seems to think quad is 24 bytes, which is absurd.
    // so we just calculate the size manually.
    gl.BufferData(gl.ARRAY_BUFFER, len(s.quad)*4, s.quad, gl.STATIC_DRAW)
    flush_errors("pre: done")

    flush_errors("creating program")
    s.program = gl.CreateProgram()

    flush_errors("created program.  creating vert shader")
    vs := gl.CreateShader(gl.VERTEX_SHADER)
    vs.Source(vertshader)
    vs.Compile()
    s.program.AttachShader(vs)
    vs.Delete()

    flush_errors("created VS.  creating FS")
    fs := gl.CreateShader(gl.FRAGMENT_SHADER)
    fs.Source(fragshader)
    fs.Compile()
    s.program.AttachShader(fs)
    fs.Delete()

    s.program.BindFragDataLocation(0, "outColor")
    s.program.Link()
    s.program.Use()

    pos := s.program.GetAttribLocation("position")
    pos.EnableArray()
    flush_errors("got attrib loc")
    pos.AttribPointer(2, gl.FLOAT, false, 0, nil)
  })
}

// Cleans up our GL objects.  Resource leak if you forget to call.
func (s s2d) Post() {
  Exec(func() {
    s.program.Delete()
    s.vertvbo.Delete()
    s.vao.Delete()
  })
}

func (s s2d) Render(data []float32, dims [2]uint) {
  Exec(func() {
    gl.DrawArrays(gl.QUADS, 0, 4)
    flush_errors("drawn")

    sdl.GL_SwapWindow(window)
    flush_errors("swapped")

    sdl.Delay(3000)
  })
}

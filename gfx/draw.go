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

func Render(data []float32, dims [2]uint) {
  Exec(func() {
    quad := []float32{
       0.9,  0.9,
       0.9, -0.9,
      -0.9, -0.9,
      -0.9,  0.9,
    }

    gfx.Trace("quad: %v\n", quad)
    gfx.Trace("data: %v\n", data)

    vao := gl.GenVertexArray()
    vao.Bind()

    flush_errors("creating buffers...")
    vertvbo := gl.GenBuffer()
    flush_errors("binding..")
    vertvbo.Bind(gl.ARRAY_BUFFER)
    flush_errors("bound.")
    flush_errors("bufdata...")
    // unsafe.Sizeof(quad) seems to think quad is 24 bytes, which is absurd.
    // so we just calculate the size manually.
    gl.BufferData(gl.ARRAY_BUFFER, len(quad)*4, quad, gl.STATIC_DRAW)

    flush_errors("creating program")
    program := gl.CreateProgram()

    flush_errors("created program.  creating vert shader")
    vs := gl.CreateShader(gl.VERTEX_SHADER)
    vs.Source(vertshader)
    vs.Compile()
    program.AttachShader(vs)
    vs.Delete()

    flush_errors("created VS.  creating FS")
    fs := gl.CreateShader(gl.FRAGMENT_SHADER)
    fs.Source(fragshader)
    fs.Compile()
    program.AttachShader(fs)
    fs.Delete()

    program.BindFragDataLocation(0, "outColor")
    program.Link()
    program.Use()

    pos := program.GetAttribLocation("position")
    pos.EnableArray()
    flush_errors("got attrib loc")
    pos.AttribPointer(2, gl.FLOAT, false, 0, nil)

    gl.DrawArrays(gl.QUADS, 0, 4)
    flush_errors("drawn")

    sdl.GL_SwapWindow(window)
    flush_errors("swapped")
    //window.UpdateSurface()

    program.Delete()
    vertvbo.Delete()
    vao.Delete()

    sdl.Delay(4000)
  })
}

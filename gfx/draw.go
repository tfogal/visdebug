package gfx

// #include <SDL2/SDL.h>
// #include <SDL2/SDL_opengl.h>
import "C"
import "github.com/go-gl/gl"
import "github.com/veandco/go-sdl2/sdl"

const tex2dname = "texScalar2D"
const vertshader = `
#version 150
in vec2 position;
out vec2 tcoord;

void main() {
  gl_Position = vec4(position, 0.0, 1.0);
  tcoord = position;
}
`
const fragshader = `
#version 150
out vec4 fragColor;
in vec2 tcoord;
uniform sampler2D texScalar2D; // must match 'tex2dname', above!
uniform float fieldmax;

void main() {
  vec2 tc = vec2(1.0-tcoord.x/2.0, tcoord.y/2.0);
  float value = texture(texScalar2D, tc).x / fieldmax;
  //fragColor = vec4(tc.x, tc.y, value, 1.0);
  //fragColor = vec4(tcoord.x, tcoord.y, value, 1.0);
  fragColor = vec4(0.0, 0.0, value, 1.0);
}
`

func flush_errors(pre string) {
  gfx.Trace(pre)
  for {
    errnum := gl.GetError()
    if errnum == 0 {
      break
    }
    gfx.Error("GL error: 0x%x\n", errnum)
  }
  for {
    msg, src, typ, id, _ := gl.GetNextDebugMessage()
    if len(msg) <= 0 {
      break
    }
    gfx.Warning("msg: '%s' from %v (type=0x%x, id=%d)", msg, src, typ, id)
  }
}

type Scalar2D interface {
  Pre()
  Render(data []float32, dims [2]uint, maximum float32)
  Post()
}

type s2d struct {
  vertvbo gl.Buffer
  vao gl.VertexArray
  program gl.Program
  quad []float32
  texture gl.Texture
  fldmaxloc gl.UniformLocation
}

func ScalarField2D() Scalar2D {
  var s s2d
  return s
}


func s2dprogram() gl.Program {
  program := gl.CreateProgram()

  flush_errors("created program.  creating vert shader")
  {
    vs := gl.CreateShader(gl.VERTEX_SHADER)
    vs.Source(vertshader)
    vs.Compile()
    gfx.Trace("vs compile log: '%s'", vs.GetInfoLog())
    program.AttachShader(vs)
    vs.Delete()
  }

  flush_errors("created VS.  creating FS")
  fs := gl.CreateShader(gl.FRAGMENT_SHADER)
  fs.Source(fragshader)
  fs.Compile()
  gfx.Trace("fs compile log: '%s'", fs.GetInfoLog())
  program.AttachShader(fs)
  fs.Delete()

  program.BindFragDataLocation(0, "fragColor")
  program.Link()
  program.Use()

  fldmax := program.GetUniformLocation("fieldmax")
  gfx.Trace("field max loc is: %v\n", fldmax)

  pos := program.GetAttribLocation("position")
  pos.EnableArray()
  pos.AttribPointer(2, gl.FLOAT, false, 0, nil)
  flush_errors("pos's attrib pointer:")

  return program
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
       1.0,  1.0,
       1.0, -1.0,
      -1.0, -1.0,
      -1.0,  1.0,
    }
    // unsafe.Sizeof(quad) seems to think quad is 24 bytes, which is absurd.
    // so we just calculate the size manually.
    gl.BufferData(gl.ARRAY_BUFFER, len(s.quad)*4, s.quad, gl.STATIC_DRAW)

    flush_errors("creating program")
    s.program = s2dprogram()
    flush_errors("program created, gen'ing texturing")

    s.texture = gl.GenTexture()
    gl.ActiveTexture(gl.TEXTURE0)
    s.texture.Bind(gl.TEXTURE_2D)

    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR)
    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR)
    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST)
    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST)
//    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_BORDER)
//    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_BORDER)
    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT)
    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.REPEAT)
    txs2d := s.program.GetUniformLocation(tex2dname)
    txs2d.Uniform1i(0)
    flush_errors("setting '" + tex2dname + "' uniform.")

    s.fldmaxloc = s.program.GetUniformLocation("fieldmax")
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

func (s s2d) Render(data []float32, dims [2]uint, maximum float32) {
  Exec(func() {
    const format = gl.LUMINANCE
    const typ = gl.FLOAT
    const intformat = gl.R32F
    flush_errors("about to set texture data...")
    gl.TexImage2D(gl.TEXTURE_2D, 0, intformat, int(dims[0]),int(dims[1]), 0,
                  format, typ, data)
    flush_errors("set texture")

    s.fldmaxloc.Uniform1f(maximum)
    flush_errors("set fieldmax uniform:")

    gl.DrawArrays(gl.QUADS, 0, 4)
    flush_errors("drawn")

    sdl.GL_SwapWindow(window)
    flush_errors("swapped")

    sdl.Delay(8000)
  })
}

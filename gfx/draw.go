package gfx

// #include <SDL2/SDL.h>
// #include <SDL2/SDL_opengl.h>
import "C"
import "os"
import "log"
import "github.com/go-gl-legacy/gl"
import "github.com/veandco/go-sdl2/sdl"

const tex2dname = "texScalar2D"
const vertshader = `
#version 300 es
in highp vec2 position;
out mediump vec2 tcoord;

void main() {
gl_Position = vec4(position, 0.0, 1.0);
tcoord = gl_Position.xy;
}
`
const fragshader = `
#version 300 es
out highp vec4 fragColor;
in mediump vec2 tcoord;
uniform sampler2D texScalar2D; // must match 'tex2dname', above!
uniform highp float fieldmax;

void main() {
  highp vec2 tc = (tcoord.xy + vec2(0.9, 0.9)) / vec2(1.8, 1.8);
  highp float value = texture(texScalar2D, tc).x / fieldmax;
  value = clamp(value, 0.0, 1.0);
  fragColor = vec4(value, 0.0, 1.0-value, 1.0);
}
`
func flush_errors(pre string) {
  for {
    errnum := gl.GetError()
    if errnum == 0 {
      break
    }
    gfx.Trace(pre)
    gfx.Error("GL error: 0x%x\n", errnum)
    os.Exit(1)
  }
  for {
    msg, src, typ, id, _ := gl.GetNextDebugMessage()
    if len(msg) <= 0 {
      break
    }
    gfx.Trace(pre)
    gfx.Warn("msg: '%s' from %v (type=0x%x, id=%d)", msg, src, typ, id)
    log.Fatalf("dying.\n")
  }
}

type Scalar2D interface {
  Pre() error
  Render(data []float32, dims []uint, maximum float32)
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
  return &s
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

  pos := program.GetAttribLocation("position")
  pos.EnableArray()
  pos.AttribPointer(2, gl.FLOAT, false, 0, nil)
  flush_errors("pos's attrib pointer:")

  return program
}

// creates the static data / OGL objects we need.  Must be called before
// 'Render'.
func (s *s2d) Pre() error {
  return Exec(func() error {
    flush_errors("pre: start")
    s.vao = gl.GenVertexArray()
    s.vao.Bind()

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

    flush_errors("creating program")
    s.program = s2dprogram()
    flush_errors("program created, gen'ing texturing")

    s.texture = gl.GenTexture()
    gl.ActiveTexture(gl.TEXTURE0)
    s.texture.Bind(gl.TEXTURE_2D)

    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR)
    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR)
    // never ever use anything but clamp to edge; others do not make any sense.
    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_R, gl.CLAMP_TO_EDGE)
    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
    gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)
    txs2d := s.program.GetUniformLocation(tex2dname)
    txs2d.Uniform1i(0)
    flush_errors("setting '" + tex2dname + "' uniform.")

    s.fldmaxloc = s.program.GetUniformLocation("fieldmax")
    gfx.Trace("field max loc is: %v\n", s.fldmaxloc)
    return nil
  })
}

// Cleans up our GL objects.  Resource leak if you forget to call.
func (s *s2d) Post() {
  Exec(func() error {
    s.program.Delete()
    s.vertvbo.Delete()
    s.vao.Delete()
    return nil
  })
}

func (s *s2d) Render(data []float32, dims []uint, maximum float32) {
  if len(dims) != 2 {
    gfx.Error("%d dimensional (%v) data cannot be handled by this 2d code",
              len(dims), dims)
    return
  }
  if dims[0]*dims[1] == 0 {
    gfx.Error("empty %dx%d field.", dims[0], dims[1])
    return
  }
  Exec(func() error {
    const format = gl.LUMINANCE
    const typ = gl.FLOAT
    const intformat = gl.R32F
    flush_errors("validating state on entry")
    if dims[0] > 8192 || dims[1] > 8192 {
      gfx.Warn("%dx%d data is too large; skipping it.", dims[0], dims[1])
      return nil
    }
    gl.TexImage2D(gl.TEXTURE_2D, 0, intformat, int(dims[0]),int(dims[1]), 0,
                  format, typ, data)
    flush_errors("set texture")

    gfx.Trace("uniform %v := %f\n", s.fldmaxloc, maximum)
    s.fldmaxloc.Uniform1f(maximum)
    flush_errors("set fieldmax uniform:")

    gl.Clear(gl.COLOR_BUFFER_BIT)

    gl.DrawArrays(gl.QUADS, 0, 4)
    flush_errors("drawn")

    sdl.GL_SwapWindow(window)
    flush_errors("swapped")
    return nil
  })
}

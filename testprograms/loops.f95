subroutine smooth1(v, n)
  implicit none
  integer :: i, n
  real, intent(inout) :: v(n)

  do i = 2, n-1
    v(i) = (v(i-1) + v(i) + v(i+1)) / 3.0
  enddo
  return
end subroutine smooth1

subroutine smooth2(v, nx, ny)
  implicit none
  integer :: x,y, nx,ny
  real, intent(inout) :: v(nx, ny)

  do x = 1, nx-1
    do y = 1, ny-1
      v(x,y) = (v(x-1,y-1) + v(x+0,y-1) + v(x+1,y-1) + &
                v(x-1,y+0) + v(x+0,y+0) + v(x+1,y+0) + &
                v(x-1,y+1) + v(x+0,y+1) + v(x+1,y+1)) / 9.0
    enddo
  enddo
end subroutine smooth2

program loops
  implicit none
  real,allocatable :: values(:)
  real,allocatable :: arr2d(:,:)
  integer :: i,j

  allocate(values(10))
  do i = 1, 10
    values(i) = real(i)**2
  enddo
  call smooth1(values, 10)
  print *,'blah:',values(3)
  deallocate(values)

  allocate(arr2d(20,30))
  do i = 1,20
    do j = 1,30
      arr2d(i,j) = i*j;
    enddo
  enddo
  print *, '2d-before(5,5):', arr2d(5,5)
  call smooth2(arr2d, 20, 30)
  print *, '2d(5,5):', arr2d(5,5)
  deallocate(arr2d)
end program loops

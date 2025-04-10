class HelloWorld {
  static {
    System.loadLibrary("HelloWorld");
  }
  int number = 69;
  private native void print();

  public static void main(String[] args) {
    new HelloWorld().print();
  }
}

package tech.simter.reactive.security.moduleauthorizer

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class StringTemplateTest {
  @Test
  fun test() {
    // %[argument_index$][flags][width][.precision]conversion
    assertThat(String.format("%2\$s, %1\$s", "a", "b")).isEqualTo("b, a")
  }
}
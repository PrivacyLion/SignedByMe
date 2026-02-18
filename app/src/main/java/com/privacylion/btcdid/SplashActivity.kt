package com.privacylion.btcdid

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

/**
 * Splash screen with animated cursive "S" handwriting effect.
 * Uses Compose Canvas with Path + dashPathEffect for authentic drawing animation.
 */
class SplashActivity : ComponentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setContent {
            SplashScreen(
                onAnimationComplete = {
                    startActivity(Intent(this, MainActivity::class.java))
                    finish()
                    overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
                }
            )
        }
    }
}

@Composable
fun SplashScreen(onAnimationComplete: () -> Unit) {
    // Animation progress from 0 to 1
    var startAnimation by remember { mutableStateOf(false) }
    
    val animationProgress by animateFloatAsState(
        targetValue = if (startAnimation) 1f else 0f,
        animationSpec = tween(
            durationMillis = 1200,
            easing = FastOutSlowInEasing
        ),
        label = "pathAnimation"
    )
    
    // Start animation after short delay
    LaunchedEffect(Unit) {
        delay(300)
        startAnimation = true
    }
    
    // Navigate after animation completes
    LaunchedEffect(animationProgress) {
        if (animationProgress >= 1f) {
            delay(500) // Pause to admire
            onAnimationComplete()
        }
    }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.linearGradient(
                    colors = listOf(
                        Color(0xFF3B82F6),
                        Color(0xFF8B5CF6)
                    ),
                    start = Offset(0f, 0f),
                    end = Offset(Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY)
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        CursiveSAnimation(
            progress = animationProgress,
            modifier = Modifier.size(200.dp)
        )
    }
}

@Composable
fun CursiveSAnimation(
    progress: Float,
    modifier: Modifier = Modifier
) {
    Canvas(modifier = modifier) {
        val width = size.width
        val height = size.height
        val strokeWidth = width * 0.08f
        
        // Build ACTUAL cursive S path - from handwriting reference
        // Cursive S is NOT like a print S - it's a flowing connected form
        val path = Path().apply {
            val cx = width / 2f
            val cy = height / 2f
            val h = height * 0.8f  // total height
            val w = width * 0.5f   // total width
            
            // TRUE CURSIVE CAPITAL S
            // Based on Palmer/Zaner-Bloser cursive handwriting
            
            // Start: top center, small entry loop going right then down
            moveTo(cx, cy - h * 0.45f)
            
            // 1. Entry loop - small curve up and right
            quadraticBezierTo(
                cx + w * 0.3f, cy - h * 0.5f,   // control: up-right
                cx + w * 0.35f, cy - h * 0.35f  // end: right side, starting down
            )
            
            // 2. Big downward swoop - curves left across the letter
            cubicTo(
                cx + w * 0.4f, cy - h * 0.1f,   // control 1: continuing down-right
                cx + w * 0.1f, cy + h * 0.05f,  // control 2: curving to center
                cx - w * 0.2f, cy + h * 0.15f   // end: left of center, below middle
            )
            
            // 3. Lower curve - sweeps down and right
            cubicTo(
                cx - w * 0.45f, cy + h * 0.25f, // control 1: far left
                cx - w * 0.4f, cy + h * 0.45f,  // control 2: bottom left
                cx, cy + h * 0.45f              // end: bottom center
            )
            
            // 4. Bottom loop - curves right and back up
            cubicTo(
                cx + w * 0.35f, cy + h * 0.45f, // control 1: bottom right
                cx + w * 0.4f, cy + h * 0.3f,   // control 2: right side going up
                cx + w * 0.2f, cy + h * 0.15f   // end: exit point
            )
            
            // 5. Exit stroke - small upward flourish
            quadraticBezierTo(
                cx + w * 0.05f, cy + h * 0.05f, // control: curving up
                cx - w * 0.1f, cy - h * 0.05f   // end: ready to connect to next letter
            )
        }
        
        // Measure path length
        val pathMeasure = android.graphics.PathMeasure(
            path.asAndroidPath(), 
            false
        )
        val pathLength = pathMeasure.length
        
        // Draw glow effect
        drawPath(
            path = path,
            color = Color.White.copy(alpha = 0.3f * progress),
            style = Stroke(
                width = strokeWidth * 2f,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
                pathEffect = PathEffect.dashPathEffect(
                    intervals = floatArrayOf(pathLength * progress, pathLength),
                    phase = 0f
                )
            )
        )
        
        // Draw main stroke with dash reveal
        drawPath(
            path = path,
            color = Color.White,
            style = Stroke(
                width = strokeWidth,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
                pathEffect = PathEffect.dashPathEffect(
                    intervals = floatArrayOf(pathLength * progress, pathLength),
                    phase = 0f
                )
            )
        )
    }
}

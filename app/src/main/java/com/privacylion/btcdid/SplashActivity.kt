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
        
        // Build cursive S path - elegant script style
        val path = Path().apply {
            // Scale factors
            val cx = width / 2f
            val cy = height / 2f
            val scale = minOf(width, height) * 0.4f
            
            // Cursive S - like handwritten script
            // Start with entry flourish at top right
            moveTo(cx + scale * 0.6f, cy - scale * 0.9f)
            
            // Entry curve going left and up
            cubicTo(
                cx + scale * 0.3f, cy - scale * 1.1f,
                cx - scale * 0.2f, cy - scale * 1.0f,
                cx - scale * 0.5f, cy - scale * 0.7f
            )
            
            // Top loop curving down and right
            cubicTo(
                cx - scale * 0.8f, cy - scale * 0.4f,
                cx - scale * 0.6f, cy - scale * 0.1f,
                cx - scale * 0.1f, cy + scale * 0.1f
            )
            
            // Middle diagonal going down-right
            cubicTo(
                cx + scale * 0.4f, cy + scale * 0.3f,
                cx + scale * 0.7f, cy + scale * 0.5f,
                cx + scale * 0.5f, cy + scale * 0.8f
            )
            
            // Bottom curve going left
            cubicTo(
                cx + scale * 0.3f, cy + scale * 1.1f,
                cx - scale * 0.2f, cy + scale * 1.0f,
                cx - scale * 0.5f, cy + scale * 0.8f
            )
            
            // Exit flourish going up-left
            cubicTo(
                cx - scale * 0.7f, cy + scale * 0.6f,
                cx - scale * 0.8f, cy + scale * 0.4f,
                cx - scale * 0.6f, cy + scale * 0.2f
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
